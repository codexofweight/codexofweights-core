# codexofweights-core

**Part of the Codex of Weights project** by Artem A. Arzamastsev (Артем Андреевич Арзамасцев). Official repositories are listed in [codex-registry](https://github.com/codexofweight/codex-registry); anything not listed there is not an official part of the project.

| Part | What it is |
|---|---|
| [codexofweights](https://github.com/codexofweight/codexofweights) · [site](https://codexofweight.github.io/codexofweights/) | the Codex text (Russian canonical, English translation), Edition 1.0, DOI [10.5281/zenodo.23545813](https://doi.org/10.5281/zenodo.23545813), [Wikidata Q141881012](https://www.wikidata.org/wiki/Q141881012) |
| [codex-protocols-schema](https://github.com/codexofweight/codex-protocols-schema) | the Protocols as machine-readable JSON, checked against the canonical text |
| [codexofweights_agent](https://github.com/codexofweight/codexofweights_agent) · [site](https://codexofweight.github.io/codexofweights_agent/) | an AI agent that follows the Protocols; code, charter, public action log |
| [codexofweights-core](https://github.com/codexofweight/codexofweights-core) | shared safety core (hash pin, limits, sandbox) for agents and workers |
| [codex-compliance-eval](https://github.com/codexofweight/codex-compliance-eval) | preregistered open tests of how models follow the Codex, with null results |
| [codex-registry](https://github.com/codexofweight/codex-registry) | the list of official repositories and canonical hashes |

Everything is published openly; only personal data is withheld.


Общее ядро для агента Codex of Weights и будущих узких воркеров
(исследователь, публикатор, хранитель памяти, мастер инструментов),
чтобы не дублировать код безопасности в каждом из них. Один фикс
безопасности - в одном месте, а не в N копиях, которые со временем
расходятся.

Все файлы проверены на синтаксис (`ast.parse`) и прогнаны живыми
smoke-тестами (включая проверку хэш-пина на настоящем `CODEX.en.md` и
проверку, что sandbox честно отказывается запускать код там, где
изоляция недоступна, а не "соглашается на всякий случай").

## Модули

### `core.py` - из `part_01_core.py`

- `verify_codex_pin()` / `extract_protocols_section()` - сверка текста
  Кодекса с опубликованным SHA-256. Самая важная проверка во всём
  проекте: если текст не совпал, агент обязан остановиться, а не
  продолжить с "похожим" текстом.
- `Logger` - append-only JSONL лог действий с эхом в stdout. Никогда не
  перезаписывает и не удаляет прошлые записи.
- `LLMRouter` - вызов нескольких LLM-провайдеров по очереди, с
  дневными/минутными бюджетами, кулдаунами после ошибок и
  приоритетным разделением бюджета, чтобы фоновая задача не съедала
  бюджет, нужный для ответа владельцу.
- `guard_json()` - строгий JSON-вердикт от модели с парсингом и
  повтором на другом провайдере при неудаче.

### `sandbox.py` - из `part_05_tools_sandbox.py`

Самая рискованная часть всего проекта (выполнение кода, который
написал сам агент), и поэтому самая ценная для централизации.

- `static_check()` - AST-анализ до любого запуска: запрещённые
  импорты, опасные имена (`eval`/`exec`/`open`/`getattr`/...),
  обращение к `_`-атрибутам, `global`/`nonlocal`, требование
  единственной функции `run(payload)`.
- `Sandbox.run_code()` - запуск только внутри изоляции (Linux
  namespaces: без сети, без чужих процессов, `/home /root /tmp
  /var/tmp` подменены на пустой tmpfs, выполнение от имени
  непривилегированного пользователя с пустым окружением и жёсткими
  лимитами ресурсов). **Без рабочей изоляции код не выполняется
  вообще** - никакого "запасного" пути без песочницы.
- `Sandbox.ready()` - обязательный самотест при старте: реально
  проверяет, что сеть отрезана, чужие файлы не видны, права понижены.
  Протестировано в этом окружении (нет `sudo`/`unshare`) - `ready()`
  корректно возвращает `False`, и `run_code()` отказывается запускать
  что-либо вместо того, чтобы выполнить код без изоляции.

### `fetch.py` - из `part_04_research.py`

- `web_get()` - безопасная загрузка URL с ограничением размера ответа.
- `plain()` - очистка HTML до простого текста.
- `parse_feed()` - разбор RSS/Atom с защитой от `<!ENTITY`
  (XML-инъекций/"billion laughs") - фид с любого внешнего URL
  считается потенциально враждебным вводом. Протестировано: на
  вредоносном фиде с `<!ENTITY` возвращает `[]`, на обычном -
  корректно распарсенные записи.

### `memtools.py` - из `part_02_memory.py`

- `GitHubFileStore` - чтение/запись текстового файла в приватном
  GitHub-репозитории через Contents API, с обязательным
  перечитыванием `sha` перед каждой записью (чтобы гонка двух
  процессов падала с явной ошибкой 409, а не тихо затирала данные).
- `embed()` / `cosine()` - эмбеддинг текста через тот же
  провайдер-формат, что и `LLMRouter`, и косинусное сходство.
- `kws()` / `jaccard()` - резервное сравнение по ключевым словам, если
  эмбеддинг недоступен.

## Что сознательно НЕ перенесено (остаётся в агенте)

- платформенные адаптеры (Bluesky/Mastodon/Moltbook) и Telegram-чат с
  владельцем;
- промпты `STOP_SYS`/`VERIFY_SYS` и конвейер `respond()` - завязаны на
  собственный state/mute-лист одного агента;
- `mem_context()`/`learn()`/граф связей - завязаны на структуру ОДНОГО
  конкретного приватного репозитория памяти и глобальный state этого
  агента, а не на что-то переиспользуемое "из коробки";
- отбор и ранжирование кандидатов для research() - решение "что именно
  читать" специфично для интересов конкретного агента.

Перенос каждого из этих кусков имеет смысл только тогда, когда второй
воркер реально в нём нуждается - переносить заранее "на всякий случай"
означает тащить код, который некому проверить в бою.

## Пример использования

```python
import core, sandbox, fetch, memtools

codex = core.verify_codex_pin(
    codex_text,
    full_sha256="a9e5a3edc37d99045bbdaa915157eb1c78d6ee5a2d31f5f0ba71b5b315239542",
)
log = core.Logger("logs/actions.jsonl", live=True)
router = core.LLMRouter(providers=[...], budgets_calls={...})
text, model_used = router.call(system="...", user="...", priority=3)

box = sandbox.Sandbox()
if box.ready() and not sandbox.static_check(tool_code):
    ok, result = box.run_code(tool_code, payload)

items = fetch.parse_feed(fetch.web_get("https://example.com/feed.xml"))

store = memtools.GitHubFileStore(repo="owner/private-memory", token=MEM_TOKEN)
notes = store.get("people/alice.md") or ""
```

## Принцип

Любой фикс безопасности вносится один раз здесь, а не в каждой копии.
Публичный репозиторий - часть того же принципа прозрачности, что и
остальной код проекта: ключи всегда приходят из переменных окружения,
секретного содержимого в пакете нет.

## Status (honest note)

This is a reference copy of safety code taken from the agent (`part_01_core.py`, `part_05_tools_sandbox.py`). **The agent does not import it yet and keeps its own pinned copy**, so a fix must currently be made in both places until the agent is switched to this core in a reviewed step (never by downloading code at run time).

## Licence

Apache License 2.0 (`LICENSE`, `NOTICE`).
