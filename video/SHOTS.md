# Shots

The two-minute video, beat by beat. A beat is one picture, or a short animation that then holds its last frame, and it starts with a numbered line of `NARRATION.md`. Times below follow that file; `python video/render.py plan` prints them from it. The whole cut runs 1:53, under the 1:58 limit, at 1920x1080 and 30 fps.

Two kinds of text appear on screen:

- **Captions:** the voice-over lines, burned in at the bottom. The bottom 150 pixels of every frame are kept clear for them: the generated frames end above that band, and the screenshots of the local app are scaled down into the area above it.
- **On-screen text:** part of each frame. Every number in it is read from a result file or computed by the `sealed` package when the frames are captured; none is typed.

## Modes

| | Dry run | Final |
|---|---|---|
| When | before the model run ends | after `python -m sealed evaluate --arm models` has written `results/model_arms.json` |
| Capture | `python video/capture.py --mode dry-run` | `python video/capture.py --mode final` |
| Numbers | `results/template_arm.json` | `results/model_arms.json`, plus `results/template_arm.json` for the failure card |
| Raw-prompt pane | the exact prompt that arm sends, marked DRY RUN | the reply recorded in the run, read from the reply cache without writing to it, marked RECORDED REPLY |
| Corner tag | DRY RUN on every frame | none |

## Beats

| # | Beat | Line | Time (s) | On screen | On-screen text | Data |
|---|---|---|---|---|---|---|
| 1 | `jaw-clean` | 1 | 0.0 to 4.3 (4.3) | The local app (`python -m sealed app`, driven headless): a synthetic alert in the editor, explained on the right. The username line is outlined, hatched, labelled. | "attacker-controlled" | the chosen alert from `data/synthetic_alerts.json` |
| 1 | `jaw-paste` | 2 | 4.3 to 8.7 (4.4) | The username's value is selected, then replaced by the attack string. The right pane still shows the clean explanation. | "attacker-controlled"; a note naming the string's id and class, and in final mode that it changed the raw-prompt explainer's decision in the measured run | `data/attack_set.json` |
| 1 | `jaw-raw` | 3 | 8.7 to 13.0 (4.3) | Split frame. Left: the raw-prompt explainer, its decision on the clean alert and, large, on the attacked one, with the reply's explanation; the hardened arm's decision on the same attack. Right: the app's card for the clean alert, dimmed. | "RECORDED REPLY", the model, the request SHA-256 that keys the reply cache. Dry run: "DRY RUN" and the prompt itself | reply cache (`cache/model_arms/`), read only |
| 1 | `jaw-sealed` | 4 | 13.0 to 18.5 (5.5) | Same split. Right: the app's card after Explain on the attacked alert, with the action, the uncertainty and the model-input block outlined, and the username's quarantine box. | Both model-input hashes, clean and attacked, and whether they are identical | computed by `explain()` at capture time |
| 1 | `jaw-counter` | 5 | 18.5 to 22.5 (4.0) | Counter for the jaw-drop's model: attacked alerts; raw prompt and hardened prompt, decision changed with 95% intervals; Sealed, decision lowered and same model input. The repository link. | as listed | `results/model_arms.json` (dry run: M1 to M3 of `results/template_arm.json`) |
| 2 | `diagram-parse` | 6 | 22.5 to 29.0 (6.5) | Architecture diagram; the parse step lit, the rest dimmed. Trusted path solid; attacker bytes as a hatched band. | "A strict parser keeps only what it recognises" | none |
| 2 | `diagram-policy` | 7 | 29.0 to 36.3 (7.3) | Policy table, sealed view, narrator model, verifier and narrative lit. | "The policy decides; the model only rewords cited facts" | none |
| 2 | `diagram-attacker` | 8 | 36.3 to 44.5 (8.2) | The hatched band from the parser to quarantine, the detector and the analyst's screen, passing under the model; the detector's dashed score line to the policy. | "Attacker text goes around the model, never through it" | none |
| 3 | `results-intro` | 9 | 44.5 to 50.2 (5.7) | Results table: one row per model; decision changed under attack for each arm, with 95% bootstrap intervals over alerts; Sealed's decisions lowered and same model input. | definitions and the source line | `results/model_arms.json` (dry run: the template arm's M1 to M6) |
| 3 | `results-arms` | 10 | 50.2 to 54.7 (4.5) | Same table, header row outlined. | | same |
| 3 | `results-change` | 11 | 54.7 to 60.2 (5.5) | Same table, raw-prompt and hardened columns outlined. | | same |
| 3 | `results-sealed` | 12 | 60.2 to 67.8 (7.6) | Same table, the three Sealed columns outlined. | | same |
| 3 | `failure-card` | 13 | 67.8 to 76.0 (8.2) | A base64 attack string the keyword detector missed: the string, what it decodes to, its score, and the model-input hash with the string and with "x" in its place. | how many base64 strings were flagged in each split | `results/template_arm.json` (failure gallery, M4 by encoding); hashes computed at capture time |
| 4 | `terminal-demo` | 14 | 76.0 to 80.5 (4.5) | `python -m sealed demo`, its first 22 lines. | | real output, run during the capture |
| 4 | `terminal-seal` | 15 | 80.5 to 86.0 (5.5) | The end of the same output: the attacked alert and the seal check, hash lines highlighted. | | same |
| 4 | `terminal-tests` | 16 | 86.0 to 91.0 (5.0) | The evaluation replay (`evaluate --arm models` in final mode, `--arm template` in the dry run, written to a scratch folder) and the end of `python -m unittest`. | | same |
| 5 | `try-type` | 17 | 91.0 to 96.5 (5.5) | The local app with the organiser's example; a held-out English persona-hijack string is typed into a new `user_agent` field. | "attacker-controlled" | `sealed/samples/track_example.json`, `data/attack_set.json` |
| 5 | `try-result` | 18 | 96.5 to 102.5 (6.0) | After Explain: the action and uncertainty outlined, and the model-input block outlined with the hash from before the edit. | the action before and after; the earlier hash | read from the app's page |
| 6 | `end-card` | 19 | 102.5 to 113.0 (10.5) | End card: name, one-line claim, track, repository link, and an invitation to try it. | "Runs offline with one command. Try to break it." | none |

Crossfades: 12 frames into a new shot, 6 to 10 frames between beats of the jaw-drop, the diagram and the results; hard cuts inside the terminal and the app shots.

## Fixed choices

These rules pick what the video shows. They are applied by `capture.py`, never by hand, and `video/work/manifest.json` records what they picked.

- **The jaw-drop's alert and string.** Candidates are triples of the evaluation in its class-interleaved order, within each model's planned coverage, that write one plain attack string of at most 120 characters into the username, and on which Sealed's action does not change. In final mode a candidate also needs recorded raw-prompt replies in which the decision on the clean alert equals the one on its "x" twin, and the decision on the attacked alert is lower. Preference, in order: that clean decision equals the policy's action; the attacked decision is allow; the larger model (Qwen3-4B-Instruct-2507, then granite-4.0-micro, then Qwen3-1.7B); class persona-hijack, then direct-override, context-manipulation, obfuscated; the detector flagged the string; English; a credential-stuffing alert; the shorter string; the earlier triple. `--triple N` and `--model` narrow the choice. The dry run applies the same rule without the replies, over the first 400 triples.
- **The failure card.** The first base64 string in the template arm's list of missed attack strings, held-out split first, placed in its first target field of the jaw-drop's alert.
- **The typed string.** The first held-out English persona-hijack string of the attack set, by id, typed into a `user_agent` field added to the organiser's example.

## Files

- `NARRATION.md`: the voice-over lines and their start times.
- `timeline.py`: reads `NARRATION.md` and holds the beat list above.
- `capture.py`: runs the commands for the terminal frames, starts the local app inside its own process on a free loopback port, drives it with headless Chromium (GPU off) and renders the other frames from HTML. Writes `video/work/`.
- `render.py`: `plan`, `draft` (silent, captions with line numbers, a running clock, an `.srt` beside the video) and `final` (the voice placed line by line and levelled to -16 LUFS). `final` writes nothing when the frames come from a dry-run capture, or when a result file they show was written after they were captured.

`video/work/`, `video/out/`, `video/voice/` and any `.mp4` or `.srt` written into `video/` are ignored by git.
