# Widget LLC — Suspicious Activity and Windows Defender Tampering

SIEM: splunk

**Вердикт:** True Positive

**Критичность:** Critical

**Affected host:** `DESKTOP-H1ATIJC.WidgetLLC.Internal`

**Affected user:** `Finance01`

**Период активности:** December 2021

**Основные IoC:**

- `2.56.59.42`
    
- `C:\Users\FINANC~1\AppData\Local\Temp\11111.exe`
    
- `C:\Users\Finance01\AppData\Local\Temp\IonicLarge.exe`
    
- `C:\Users\Finance01\AppData\Roaming\EasyCalc\EasyCalc.exe`
    

### Анализ

В ходе расследования событий Sysmon на рабочей станции сотрудника финансового отдела Widget LLC была обнаружена последовательность подозрительной активности, связанной с запуском потенциально вредоносных исполняемых файлов и изменением настроек Windows Defender

Первоначально был обнаружен запуск инструмента Web Browser Password Viewer из временной директории пользователя:

`C:\Users\FINANC~1\AppData\Local\Temp\11111.exe`

В свойствах исполняемого файла в качестве компании-издателя указана NirSoft. Данный инструмент предназначен для просмотра сохранённых браузером паролей. Его запуск на рабочей станции финансового аналитика представляет риск компрометации учётных данных

Далее был обнаружен запуск другого подозрительного исполняемого файла из той же директории:

`C:\Users\Finance01\AppData\Local\Temp\IonicLarge.exe`

В метаданных файла в качестве OriginalFileName указано `PalitExplorer.exe`, которое отличается от названия самого процесса, что является дополнительным признаком подозрительной активности

При анализе сетевых событий Sysmon (Event ID 3) установлено, что `IonicLarge.exe` совершил два исходящих сетевых подключения к IP-адресу `2.56.59.42`

Также обнаружены изменения в реестре Windows Defender (Sysmon Event ID 13). Были изменены следующие параметры:

- `DisableAntiSpyware`
    
- `DisableRoutinelyTakingAction`
    
- `DisableBehaviorMonitoring`
    
- `DisableIOAVProtection`
    
- `DisableOnAccessProtection`
    
- `DisableRawWriteNotification`
    
- `DisableRealtimeMonitoring`
    
- `DisableScanOnRealtimeEnable`
    

Изменения затрагивали разделы:

`HKLM\SOFTWARE\Policies\Microsoft\Windows Defender`

`HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection`

Данная активность указывает на попытку ослабить механизмы защиты Windows Defender

Была обнаружена последовательность команд PowerShell, изменяющих поведение Windows Defender. В ходе выполнения команд злоумышленник установил четыре значения ThreatIDDefaultAction:

`2147735503`, `2147737010`, `2147737007`, `2147737394`.

Последняя обнаруженная команда:

`powershell WMIC /NAMESPACE:\root\Microsoft\Windows\Defender PATH MSFT_MpPreference call Add ThreatIDDefaultAction_Ids=2147737394 ThreatIDDefaultAction_Actions=6 Force=True`

Дополнительно выявлен запуск подозрительного файла из другой директории AppData:

`C:\Users\Finance01\AppData\Roaming\EasyCalc\EasyCalc.exe`

Проверка SHA-256 файла через VirusTotal показала вредоносные детекты. При анализе логов была замечена выгрузка dll файлов из директории `EasyCalc`:
- `ffmpeg.dll`
    
- `nw.dll`
    
- `nw_elf.dll`

Также обнаружено выполнение `taskkill.exe`, после которого были завершены процессы и удалены связанные с ними исполняемые файлы:

- `WvmIOrcfsuILdX6SNwIRmGOJ.exe`
    
- `phcIAmLJMAIMSa9j9MpgJo1m.exe`
    

Это может свидетельствовать о попытке остановить связанные с атакой процессы и удалить их файлы с системы

### Заключение

Инцидент классифицирован как **True Positive**. На рабочей станции `DESKTOP-H1ATIJC` обнаружена совокупность подозрительных действий: запуск инструмента для просмотра сохранённых браузерных паролей, выполнение подозрительных бинарных файлов, сетевые подключения к внешнему IP, изменение параметров Windows Defender и загрузка dll из директории вредоносного приложения

Совокупность событий указывает на вероятную компрометацию рабочей станции и попытку ослабления средств защиты для дальнейшей активности

Использование Web Browser Password Viewer создаёт риск утечки учётных данных. Однако факт успешной кражи паролей на основании имеющихся событий не подтверждён. Также необходимо дополнительное исследование файлов `IonicLarge.exe`, `EasyCalc.exe` и загруженных dll 

### Рекомендации

1. Изолировать рабочую станцию `DESKTOP-H1ATIJC` 
    
2. Заблокировать IP-адрес `2.56.59.42` и проверить наличие соединений с ним на других хостах
    
3. Поместить обнаруженные подозрительные исполняемые файлы и DLL в карантин
    
4. Проверить хэши обнаруженных файлов на остальных рабочих станциях организации
    
5. Сменить пароли пользователя
    
6. Восстановить настройки Windows Defender
    
7. Провести анализ `IonicLarge.exe`, `EasyCalc.exe` и библиотек `ffmpeg.dll`, `nw.dll`, `nw_elf.dll` в песочнице
    
8. Проверить систему на наличие методов закрепления 