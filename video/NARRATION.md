# Voice-over

The voice-over for the two-minute video, one numbered line per recording. Each line starts at the time in bold; the pictures and the captions follow the same times (see `SHOTS.md`). The lines hold no measured numbers: every result appears on screen, read from the result files when the frames are captured.

Spoken at 150 words a minute the lines take about 1:32 of the 1:53 the video runs, and each line ends with a pause before the next one starts.

## Lines

### Shot 1. The attack

1. **0:00.0** Every security alert carries text the attacker wrote.
2. **0:04.3** Here, the username. They write an instruction into it.
3. **0:08.7** An AI explainer reads it, and changes its answer.
4. **0:13.0** Sealed holds. Same action, and the same model input, byte for byte.
5. **0:18.5** Its model never reads what the attacker wrote.

### Shot 2. How it works

6. **0:22.5** Here's how. A strict parser turns the alert into codes from a fixed list.
7. **0:29.0** A declared policy picks the action. The model only rewords those facts, citing each one.
8. **0:36.3** Free text goes around the model, into quarantine. Text that reads like an instruction counts against the attacker.

### Shot 3. Results

9. **0:44.5** We tested three local models against our attack strings, on synthetic alerts.
10. **0:50.2** Raw prompt, hardened prompt, and Sealed, on the same alerts.
11. **0:54.7** This is how often each decision changed under attack.
12. **1:00.2** Sealed's model input never changed. Its action can only rise one level, when the attack is caught.
13. **1:07.8** The detector missed this base64 string. That costs only the warning: the model never reads it.

### Shot 4. Run it

14. **1:16.0** It runs offline. One command, no installs, no keys.
15. **1:20.5** The demo prints the seal check. Clean alert, attacked alert, same hash.
16. **1:26.0** The tests fuzz thousands of values through every free-text field.

### Shot 5. Try to break it

17. **1:31.0** Try to break it. Put anything into any free-text field.
18. **1:36.5** Whatever you write, the action never goes down, and the hash doesn't move.

### Shot 6. Limits

19. **1:42.5** The limits: the alerts are synthetic, and the explanations have not been tested with real analysts.

The video ends at **1:53.0**, after 10.5 seconds on the end card.
