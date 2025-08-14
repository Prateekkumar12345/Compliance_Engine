import requests
import json
import datetime
from typing import Dict, List, Any, Optional
import csv
import os
from dataclasses import dataclass
from collections import defaultdict
import time

@dataclass
class ComplianceEvent:
    timestamp: str
    event_type: str
    repository: str
    user: str
    details: Dict[str, Any]
    compliance_score: float

class GitHubComplianceEngine:
    def __init__(self, github_token: str, repositories: List[str], organization: Optional[str] = None):
        """
        Initialize the compliance engine
        
        Args:
            github_token: Your GitHub personal access token
            repositories: List of repository names to monitor (e.g., ['repo1', 'repo2'])
            organization: Optional organization name (if not provided, uses authenticated user's repos)
        """
        self.token = github_token
        self.repositories = repositories
        self.organization = organization
        self.headers = {
            'Authorization': f'token {github_token}',
            'Accept': 'application/vnd.github.v3+json'
        }
        self.base_url = 'https://api.github.com'
        self.events = []
        
    def get_repositories(self, repo_name: Optional[str] = None) -> List[Dict]:
        """Get repositories to monitor based on the specified repository list"""
        repositories = []
        
        # If specific repo requested, get just that one
        if repo_name and repo_name in self.repositories:
            if self.organization:
                repo_full_name = f"{self.organization}/{repo_name}"
            else:
                # Get authenticated user info to construct full name
                user_response = requests.get(f"{self.base_url}/user", headers=self.headers)
                if user_response.status_code == 200:
                    username = user_response.json()['login']
                    repo_full_name = f"{username}/{repo_name}"
                else:
                    repo_full_name = repo_name  # fallback
            
            url = f"{self.base_url}/repos/{repo_full_name}"
            try:
                response = requests.get(url, headers=self.headers)
                response.raise_for_status()
                return [response.json()]
            except requests.exceptions.RequestException as e:
                print(f"Error fetching repository {repo_name}: {e}")
                return []
        
        # Get all specified repositories
        for repo_name in self.repositories:
            if self.organization:
                repo_full_name = f"{self.organization}/{repo_name}"
            else:
                # Get authenticated user info to construct full name
                user_response = requests.get(f"{self.base_url}/user", headers=self.headers)
                if user_response.status_code == 200:
                    username = user_response.json()['login']
                    repo_full_name = f"{username}/{repo_name}"
                else:
                    repo_full_name = repo_name  # fallback
            
            url = f"{self.base_url}/repos/{repo_full_name}"
            try:
                response = requests.get(url, headers=self.headers)
                response.raise_for_status()
                repositories.append(response.json())
            except requests.exceptions.RequestException as e:
                print(f"Error fetching repository {repo_name}: {e}")
                continue
        
        return repositories

    def monitor_commits(self, repo_full_name: str, days_back: int = 30) -> List[ComplianceEvent]:
        """Monitor commits for a repository"""
        since_date = (datetime.datetime.now() - datetime.timedelta(days=days_back)).isoformat()
        url = f"{self.base_url}/repos/{repo_full_name}/commits"
        
        events = []
        try:
            response = requests.get(url, headers=self.headers, params={
                'since': since_date,
                'per_page': 100
            })
            response.raise_for_status()
            commits = response.json()
            
            for commit in commits:
                event = ComplianceEvent(
                    timestamp=commit['commit']['committer']['date'],
                    event_type='commit',
                    repository=repo_full_name,
                    user=commit['commit']['author']['name'],
                    details={
                        'sha': commit['sha'],
                        'message': commit['commit']['message'],
                        'files_changed': len(commit.get('files', [])),
                        'additions': sum(f.get('additions', 0) for f in commit.get('files', [])),
                        'deletions': sum(f.get('deletions', 0) for f in commit.get('files', []))
                    },
                    compliance_score=self._calculate_commit_compliance_score(commit)
                )
                events.append(event)
                
        except requests.exceptions.RequestException as e:
            print(f"Error fetching commits for {repo_full_name}: {e}")
            
        return events

    def monitor_pull_requests(self, repo_full_name: str, state: str = 'all') -> List[ComplianceEvent]:
        """Monitor pull requests"""
        url = f"{self.base_url}/repos/{repo_full_name}/pulls"
        
        events = []
        try:
            response = requests.get(url, headers=self.headers, params={
                'state': state,
                'per_page': 100
            })
            response.raise_for_status()
            pulls = response.json()
            
            for pr in pulls:
                event = ComplianceEvent(
                    timestamp=pr['created_at'],
                    event_type='pull_request',
                    repository=repo_full_name,
                    user=pr['user']['login'],
                    details={
                        'number': pr['number'],
                        'title': pr['title'],
                        'state': pr['state'],
                        'merged': pr.get('merged', False),
                        'mergeable': pr.get('mergeable'),
                        'review_comments': pr.get('review_comments', 0)
                    },
                    compliance_score=self._calculate_pr_compliance_score(pr)
                )
                events.append(event)
                
        except requests.exceptions.RequestException as e:
            print(f"Error fetching pull requests for {repo_full_name}: {e}")
            
        return events

    def monitor_file_operations(self, repo_full_name: str) -> List[ComplianceEvent]:
        """Monitor file operations through repository events"""
        url = f"{self.base_url}/repos/{repo_full_name}/events"
        
        events = []
        try:
            response = requests.get(url, headers=self.headers, params={'per_page': 100})
            response.raise_for_status()
            repo_events = response.json()
            
            for event in repo_events:
                if event['type'] in ['PushEvent', 'CreateEvent', 'DeleteEvent']:
                    compliance_event = ComplianceEvent(
                        timestamp=event['created_at'],
                        event_type=f"file_{event['type'].lower()}",
                        repository=repo_full_name,
                        user=event['actor']['login'],
                        details={
                            'event_id': event['id'],
                            'payload': event.get('payload', {}),
                            'ref': event.get('payload', {}).get('ref', ''),
                            'commits_count': len(event.get('payload', {}).get('commits', []))
                        },
                        compliance_score=self._calculate_file_operation_compliance_score(event)
                    )
                    events.append(compliance_event)
                    
        except requests.exceptions.RequestException as e:
            print(f"Error fetching events for {repo_full_name}: {e}")
            
        return events

    def monitor_branches_and_tags(self, repo_full_name: str) -> List[ComplianceEvent]:
        """Monitor branches and tags"""
        events = []
        
        # Monitor branches
        try:
            url = f"{self.base_url}/repos/{repo_full_name}/branches"
            response = requests.get(url, headers=self.headers, params={'per_page': 100})
            response.raise_for_status()
            branches = response.json()
            
            for branch in branches:
                event = ComplianceEvent(
                    timestamp=datetime.datetime.now().isoformat(),
                    event_type='branch_status',
                    repository=repo_full_name,
                    user='system',
                    details={
                        'name': branch['name'],
                        'protected': branch.get('protected', False),
                        'commit_sha': branch['commit']['sha']
                    },
                    compliance_score=1.0 if branch.get('protected') else 0.7
                )
                events.append(event)
                
        except requests.exceptions.RequestException as e:
            print(f"Error fetching branches for {repo_full_name}: {e}")
        
        # Monitor tags
        try:
            url = f"{self.base_url}/repos/{repo_full_name}/tags"
            response = requests.get(url, headers=self.headers, params={'per_page': 50})
            response.raise_for_status()
            tags = response.json()
            
            for tag in tags:
                event = ComplianceEvent(
                    timestamp=datetime.datetime.now().isoformat(),
                    event_type='tag_status',
                    repository=repo_full_name,
                    user='system',
                    details={
                        'name': tag['name'],
                        'commit_sha': tag['commit']['sha']
                    },
                    compliance_score=0.9
                )
                events.append(event)
                
        except requests.exceptions.RequestException as e:
            print(f"Error fetching tags for {repo_full_name}: {e}")
            
        return events

    def _calculate_commit_compliance_score(self, commit: Dict) -> float:
        """Calculate compliance score for a commit"""
        score = 1.0
        message = commit['commit']['message'].lower()
        
        # Check commit message quality
        if len(commit['commit']['message']) < 10:
            score -= 0.3
        
        # Check for conventional commit format
        if not any(prefix in message for prefix in ['feat:', 'fix:', 'docs:', 'style:', 'refactor:', 'test:', 'chore:']):
            score -= 0.2
            
        # Check for large commits (potential issue)
        files_changed = len(commit.get('files', []))
        if files_changed > 20:
            score -= 0.2
            
        return max(0.0, score)

    def _calculate_pr_compliance_score(self, pr: Dict) -> float:
        """Calculate compliance score for a pull request"""
        score = 1.0
        
        # Check if PR has description
        if not pr.get('body') or len(pr['body']) < 20:
            score -= 0.3
            
        # Check if PR is reviewed
        if pr.get('review_comments', 0) == 0:
            score -= 0.2
            
        # Check PR size (too large might be an issue)
        if pr.get('additions', 0) + pr.get('deletions', 0) > 1000:
            score -= 0.1
            
        return max(0.0, score)

    def _calculate_file_operation_compliance_score(self, event: Dict) -> float:
        """Calculate compliance score for file operations"""
        score = 1.0
        
        # Different event types have different base scores
        if event['type'] == 'PushEvent':
            commits_count = len(event.get('payload', {}).get('commits', []))
            if commits_count > 10:  # Large batch push might be risky
                score -= 0.2
        elif event['type'] == 'DeleteEvent':
            score = 0.8  # Deletions are riskier
        
        return max(0.0, score)

    def run_comprehensive_scan(self, days_back: int = 30) -> List[ComplianceEvent]:
        """Run a comprehensive compliance scan on specified repositories"""
        all_events = []
        
        repositories = self.get_repositories()
        
        print(f"Scanning {len(repositories)} specified repositories...")
        
        for repo in repositories:
            repo_full_name = repo['full_name']
            print(f"Scanning repository: {repo_full_name}")
            
            # Monitor different aspects
            all_events.extend(self.monitor_commits(repo_full_name, days_back))
            all_events.extend(self.monitor_pull_requests(repo_full_name))
            all_events.extend(self.monitor_file_operations(repo_full_name))
            all_events.extend(self.monitor_branches_and_tags(repo_full_name))
            
            # Rate limiting
            time.sleep(1)
        
        self.events = all_events
        return all_events

    def generate_progress_report(self, output_file: str = 'compliance_report.json') -> Dict[str, Any]:
        """Generate a comprehensive progress report"""
        if not self.events:
            print("No events to analyze. Run a scan first.")
            return {}
        
        # Aggregate data
        report = {
            'generated_at': datetime.datetime.now().isoformat(),
            'scan_period': f"Last 30 days",
            'total_events': len(self.events),
            'repositories_scanned': len(set(event.repository for event in self.events)),
            'summary': self._generate_summary(),
            'compliance_metrics': self._generate_compliance_metrics(),
            'detailed_events': [
                {
                    'timestamp': event.timestamp,
                    'type': event.event_type,
                    'repository': event.repository,
                    'user': event.user,
                    'compliance_score': event.compliance_score,
                    'details': event.details
                }
                for event in sorted(self.events, key=lambda x: x.timestamp, reverse=True)
            ]
        }
        
        # Save to file
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        print(f"Compliance report generated: {output_file}")
        return report

    def _generate_summary(self) -> Dict[str, Any]:
        """Generate summary statistics"""
        events_by_type = defaultdict(int)
        events_by_repo = defaultdict(int)
        events_by_user = defaultdict(int)
        
        for event in self.events:
            events_by_type[event.event_type] += 1
            events_by_repo[event.repository] += 1
            events_by_user[event.user] += 1
        
        return {
            'events_by_type': dict(events_by_type),
            'events_by_repository': dict(events_by_repo),
            'top_contributors': dict(sorted(events_by_user.items(), key=lambda x: x[1], reverse=True)[:10]),
            'average_compliance_score': sum(event.compliance_score for event in self.events) / len(self.events) if self.events else 0
        }

    def _generate_compliance_metrics(self) -> Dict[str, Any]:
        """Generate compliance-specific metrics"""
        total_events = len(self.events)
        if total_events == 0:
            return {}
        
        high_risk_events = [e for e in self.events if e.compliance_score < 0.5]
        medium_risk_events = [e for e in self.events if 0.5 <= e.compliance_score < 0.8]
        low_risk_events = [e for e in self.events if e.compliance_score >= 0.8]
        
        return {
            'risk_distribution': {
                'high_risk': len(high_risk_events),
                'medium_risk': len(medium_risk_events),
                'low_risk': len(low_risk_events)
            },
            'risk_percentages': {
                'high_risk': (len(high_risk_events) / total_events) * 100,
                'medium_risk': (len(medium_risk_events) / total_events) * 100,
                'low_risk': (len(low_risk_events) / total_events) * 100
            },
            'compliance_trends': self._analyze_compliance_trends(),
            'recommendations': self._generate_recommendations(high_risk_events)
        }

    def _analyze_compliance_trends(self) -> Dict[str, Any]:
        """Analyze compliance trends over time"""
        # Group events by day
        daily_scores = defaultdict(list)
        
        for event in self.events:
            try:
                date = datetime.datetime.fromisoformat(event.timestamp.replace('Z', '+00:00')).date()
                daily_scores[date].append(event.compliance_score)
            except:
                continue
        
        # Calculate daily averages
        daily_averages = {
            date.isoformat(): sum(scores) / len(scores)
            for date, scores in daily_scores.items()
        }
        
        return {
            'daily_compliance_scores': daily_averages,
            'trend': 'improving' if len(daily_averages) > 1 and 
                    list(daily_averages.values())[-1] > list(daily_averages.values())[0] 
                    else 'stable'
        }

    def _generate_recommendations(self, high_risk_events: List[ComplianceEvent]) -> List[str]:
        """Generate recommendations based on high-risk events"""
        recommendations = []
        
        # Analyze high-risk patterns
        commit_issues = [e for e in high_risk_events if e.event_type == 'commit']
        pr_issues = [e for e in high_risk_events if e.event_type == 'pull_request']
        
        if commit_issues:
            recommendations.append("Improve commit message quality and follow conventional commit format")
            recommendations.append("Consider breaking down large commits into smaller, focused changes")
        
        if pr_issues:
            recommendations.append("Ensure all pull requests have detailed descriptions")
            recommendations.append("Implement mandatory code reviews for all pull requests")
        
        if not recommendations:
            recommendations.append("Overall compliance is good. Continue current practices.")
        
        return recommendations



# Example usage
def main():
    repositories_to_monitor = [
        'krivisio'
    ]
    
    engine = GitHubComplianceEngine(
        github_token='', 
        repositories=repositories_to_monitor,
        organization=''  # Optional: replace with your org name or remove
    )
    
    # Run comprehensive scan
    print("Starting compliance scan...")
    events = engine.run_comprehensive_scan(days_back=30)
    
    print(f"Found {len(events)} events to analyze")
    
    # Generate report
    report = engine.generate_progress_report('compliance_report.json')
    
    # Print summary
    print("\n=== COMPLIANCE SUMMARY ===")
    print(f"Total Events: {report['total_events']}")
    print(f"Repositories Scanned: {report['repositories_scanned']}")
    print(f"Average Compliance Score: {report['summary']['average_compliance_score']:.2f}")
    
    print("\nRisk Distribution:")
    metrics = report['compliance_metrics']
    print(f"High Risk: {metrics['risk_distribution']['high_risk']} ({metrics['risk_percentages']['high_risk']:.1f}%)")
    print(f"Medium Risk: {metrics['risk_distribution']['medium_risk']} ({metrics['risk_percentages']['medium_risk']:.1f}%)")
    print(f"Low Risk: {metrics['risk_distribution']['low_risk']} ({metrics['risk_percentages']['low_risk']:.1f}%)")
    
    print("\nRecommendations:")
    for rec in metrics['recommendations']:
        print(f"- {rec}")

if __name__ == "__main__":
    main()