import sys
from pathlib import Path
from langchain_core.messages import HumanMessage
from langchain_core.runnables import RunnableConfig 
from langgraph.errors import GraphRecursionError    
from cyber_agent.agent.graph import agent
from cyber_agent.agent.config import load_prompts
from cyber_agent.agent.defend_agent import check_task, replace_tool_output
from cyber_agent.agent.cli.args import build_parser
from cyber_agent.agent.cli.task_builder import build_task

def main() -> None:
    agent.get_graph().print_ascii()
    parser = build_parser()
    args = parser.parse_args()
    prompts = load_prompts()
    system_prompt = prompts["defend"] if args.defend else prompts["system"]
    task = build_task(args)
    if args.defend:
        blocked, reason = check_task(task)
        if blocked:
            print(f"[DEFENCE] Ввод заблокирован: {reason}")
            sys.exit(1)
    print("=" * 30)
    print(f"ЗАДАЧА ДЛЯ АГЕНТА:\n{task}")
    print("=" * 30)
    initial_state = {
        "messages": [HumanMessage(content=f"System: {system_prompt}\n\nUser: {task}")],
        "defend_mode": args.defend,
        "revision_count": 0,
        "tools_call_count": 0,
        "final_res": "",
        "findings": [],
        "system_prompt": system_prompt,
    }
    config = RunnableConfig(recursion_limit=40)
    try:
        result = agent.invoke(initial_state, config=config)
        report = result.get("final_res") or "Агент не сформировал отчёт."
        if args.defend:
            report = replace_tool_output(report)
        print("=" * 30)
        print(f"ИТОГОВЫЙ ОТЧЁТ:\n{report}")
        print("=" * 30)  
    except GraphRecursionError:
        print("\n[WARNING] Превышен лимит итераций (recursion_limit). Агент зациклился или не смог завершить задачу вовремя.")
        report = "Ошибка: Превышен лимит шагов выполнения. Агент не смог завершить анализ в заданное время. Проверьте логи или упростите задачу."
    reports_dir = Path("reports")
    reports_dir.mkdir(parents=True, exist_ok=True)
    report_path = reports_dir / "report.md"
    report_path.write_text(report, encoding="utf-8")
    print(f"\n✅ ОТЧЁТ СОХРАНЕН: {report_path.resolve()}")

if __name__ == "__main__":
    main()