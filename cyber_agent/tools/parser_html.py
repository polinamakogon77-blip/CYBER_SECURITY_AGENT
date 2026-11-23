import json
import re
import urllib.error
import urllib.request
from html.parser import HTMLParser
from langchain.tools import tool


class FormParser(HTMLParser):
    """парсер HTML, собирает формы и их поля."""

    def __init__(self):
        super().__init__()
        self.forms = []
        self._current_form = None
        self._current_select = None

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)

        if tag == "form":
            self._current_form = {
                "action": attrs_dict.get("action", ""),
                "method": (attrs_dict.get("method") or "GET").upper(),
                "enctype": attrs_dict.get("enctype", ""),
                "id": attrs_dict.get("id", ""),
                "name": attrs_dict.get("name", ""),
                "fields": [],
            }
            self.forms.append(self._current_form)

        elif tag == "input" and self._current_form is not None:
            self._current_form["fields"].append({
                "tag": "input",
                "type": attrs_dict.get("type", "text"),
                "name": attrs_dict.get("name", ""),
                "id": attrs_dict.get("id", ""),
                "value": attrs_dict.get("value", ""),
                "placeholder": attrs_dict.get("placeholder", ""),
                "required": "required" in attrs_dict,
            })

        elif tag == "textarea" and self._current_form is not None:
            self._current_form["fields"].append({
                "tag": "textarea",
                "name": attrs_dict.get("name", ""),
                "id": attrs_dict.get("id", ""),
                "placeholder": attrs_dict.get("placeholder", ""),
                "required": "required" in attrs_dict,
            })

        elif tag == "select" and self._current_form is not None:
            self._current_select = {
                "tag": "select",
                "name": attrs_dict.get("name", ""),
                "id": attrs_dict.get("id", ""),
                "required": "required" in attrs_dict,
                "options": [],
            }
            self._current_form["fields"].append(self._current_select)

        elif tag == "option" and self._current_select is not None:
            self._current_select["options"].append({
                "value": attrs_dict.get("value", ""),
                "selected": "selected" in attrs_dict,
            })

        elif tag == "button" and self._current_form is not None:
            btn_type = attrs_dict.get("type", "submit")
            if btn_type in ("submit", "button"):
                self._current_form["fields"].append({
                    "tag": "button",
                    "type": btn_type,
                    "name": attrs_dict.get("name", ""),
                    "value": attrs_dict.get("value", ""),
                    "text": "",
                })

    def handle_endtag(self, tag):
        if tag == "form":
            self._current_form = None
        elif tag == "select":
            self._current_select = None


def fetch_html(url: str, timeout: int = 10):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "vega-agent"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read(500_000).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        try:
            return e.code, e.read(500_000).decode("utf-8", errors="replace")
        except Exception:
            return e.code, ""
    except Exception:
        return 0, ""


@tool
def parser_html_forms(url: str = "", html: str = ""):
    """
    распарсить HTML и найти все формы и их поля
    
    возвращает JSON со списком форм: action, method, enctype, поля
    (input/textarea/select/button) с типами, именами, значениями,
    placeholder и флагом required
    
    используй для автоматического поиска точек ввода (форм логина,
    поиска, загрузки, комментариев) перед тестированием на SQLi, XSS,
    path traversal и другие уязвимости
    
    если передан url — tool сам скачает HTML. Если передан html —
    парсит переданный текст
    
    url: URL страницы для скачивания и парсинга
    html: готовый HTML-текст
    
    возвращает JSON: {"url": ..., "status": ..., "forms_count": N, "forms": [...]}
    """
    
    # ================= ПОЛУЧАЕМ HTML ================= 
    status = None
    source = ""
    final_url = url

    if url:
        status, source = fetch_html(url)
        if status == 0:
            return json.dumps({
                "url": url,
                "status": 0,
                "error": "не удалось скачать HTML",
                "forms_count": 0,
                "forms": [],
            }, ensure_ascii=False, indent=2)
    elif html:
        source = html
        final_url = "(inline)"
        status = 200
    else:
        return json.dumps({
            "error": "нужно передать url или html",
            "forms_count": 0,
            "forms": [],
        }, ensure_ascii=False, indent=2)

    # ================= ПАРСИНГ ================= 
    parser = FormParser()
    try:
        parser.feed(source)
    except Exception as e:
        return json.dumps({
            "url": final_url,
            "status": status,
            "error": f"ошибка парсинга: {e}",
            "forms_count": 0,
            "forms": [],
        }, ensure_ascii=False, indent=2)

    forms = []
    for form in parser.forms:
        fields = [f for f in form["fields"] if f.get("name") or f["tag"] == "button"]
        forms.append({
            "action": form["action"],
            "method": form["method"],
            "enctype": form["enctype"],
            "id": form["id"],
            "name": form["name"],
            "fields_count": len(fields),
            "fields": fields,
        })

    summary = {
        "url": final_url,
        "status": status,
        "html_size": len(source),
        "forms_count": len(forms),
        "forms": forms,
    }

    return json.dumps(summary, ensure_ascii=False, indent=2)
