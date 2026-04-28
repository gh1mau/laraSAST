import os
import json
import requests
from rich.console import Console

class AIAnalyzer:
    def __init__(self, console, api_key, model_name="mistralai/mistral-7b-instruct-v0.2"):
        self.console = console
        self.api_key = api_key
        self.model_name = model_name
        self.base_url = "https://openrouter.ai/api/v1"

    def list_models(self):
        """Lists available models from OpenRouter."""
        if not self.api_key:
            self.console.print("[bold red]Error:[/bold red] API Key is missing.")
            return

        self.console.print("\n[bold cyan]Fetching available models from OpenRouter...[/bold cyan]")
        try:
            response = requests.get(f"{self.base_url}/models", headers={"Authorization": f"Bearer {self.api_key}"})
            response.raise_for_status()
            models = response.json().get('data', [])
            
            # Paparkan 15 model pertama yang popular/percuma untuk mengelakkan senarai terlalu panjang
            for m in models[:20]:
                name = m.get('id')
                pricing = m.get('pricing', {})
                is_free = "FREE" if pricing.get('prompt') == "0" else ""
                self.console.print(f" - [green]{name}[/green] [bold yellow]{is_free}[/bold yellow]")
            
            self.console.print("\n[dim]* Refer to https://openrouter.ai/models for full list.[/dim]")
        except Exception as e:
            self.console.print(f"[bold red]Error fetching models:[/bold red] {str(e)}")

    def analyze(self, findings):
        if not self.api_key:
            self.console.print("[bold yellow]![/bold yellow] Skipping AI analysis: API Key is missing.")
            return findings

        with self.console.status(f"[bold purple]AI ({self.model_name} via OpenRouter) is analyzing findings...", spinner="bouncingBar"):
            try:
                # Prepare a compact version of findings to save tokens
                minimal_findings = []
                for i, f in enumerate(findings):
                    minimal_findings.append({
                        "id": i,
                        "module": f.get('module'),
                        "issue": f.get('issue'),
                        "severity": f.get('severity')
                    })

                prompt = f"""
                As a world-class Cyber Security Researcher, analyze these Laravel security findings.
                For each finding, provide:
                1. A brief Proof of Concept (PoC) scenario for exploitation.
                2. Robust mitigation steps specific to Laravel best practices.

                Respond ONLY with a valid JSON array of objects. Each object MUST have:
                "id": (matching the input ID),
                "poc": "Short PoC description",
                "mitigation": "Laravel-specific mitigation steps"

                Findings to analyze:
                {json.dumps(minimal_findings)}
                """

                headers = {
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                    "HTTP-Referer": "https://github.com/masta-ghimau/lara-sast"
                }
                
                payload = {
                    "model": self.model_name,
                    "messages": [
                        {"role": "system", "content": "You are a Cyber Security Expert. Return only JSON."},
                        {"role": "user", "content": prompt}
                    ]
                }

                response = requests.post(f"{self.base_url}/chat/completions", headers=headers, json=payload)
                response.raise_for_status()
                
                res_data = response.json()
                raw_response = res_data['choices'][0]['message']['content'].strip()
                
                # Clean AI response if it contains markdown code blocks
                if "```json" in raw_response:
                    raw_response = raw_response.split("```json")[1].split("```")[0].strip()
                elif "```" in raw_response:
                    raw_response = raw_response.split("```")[1].split("```")[0].strip()

                ai_data = json.loads(raw_response)
                
                for item in ai_data:
                    idx = item.get('id')
                    if idx is not None and idx < len(findings):
                        findings[idx]['ai_poc'] = item.get('poc')
                        findings[idx]['ai_mitigation'] = item.get('mitigation')

            except json.JSONDecodeError:
                self.console.print(f"[bold red]AI Analysis Error:[/bold red] Failed to parse AI response. Raw: {raw_response[:100]}...")
            except Exception as e:
                self.console.print(f"[bold red]AI Analysis Error:[/bold red] {str(e)}")

        return findings