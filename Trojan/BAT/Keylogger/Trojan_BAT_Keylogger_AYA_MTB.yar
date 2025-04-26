
rule Trojan_BAT_Keylogger_AYA_MTB{
	meta:
		description = "Trojan:BAT/Keylogger.AYA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {72 58 01 00 70 18 28 17 00 00 0a 11 05 11 04 6f 18 00 00 0a de 0c 11 05 2c 07 11 05 6f 19 00 00 0a dc 1b 28 1a 00 00 0a 72 68 01 00 70 28 1b 00 00 0a 17 73 16 00 00 0a 13 06 1b 28 1a 00 00 0a 72 68 01 00 70 28 1b 00 00 0a 18 28 17 00 00 0a } //2
		$a_01_1 = {6b 65 79 6c 6f 67 67 65 72 2e 65 78 65 } //1 keylogger.exe
		$a_00_2 = {70 00 65 00 72 00 73 00 69 00 73 00 74 00 65 00 6e 00 63 00 65 00 5f 00 74 00 72 00 75 00 65 00 } //1 persistence_true
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1) >=4
 
}
rule Trojan_BAT_Keylogger_AYA_MTB_2{
	meta:
		description = "Trojan:BAT/Keylogger.AYA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 08 00 00 "
		
	strings :
		$a_01_0 = {43 6f 63 43 6f 63 43 72 61 73 68 48 61 6e 64 6c 65 72 2e 70 64 62 } //2 CocCocCrashHandler.pdb
		$a_01_1 = {54 65 6c 65 67 72 61 6d 2e 42 6f 74 2e 54 79 70 65 73 } //2 Telegram.Bot.Types
		$a_01_2 = {4b 69 6c 6c 53 61 6d 65 50 72 6f 63 65 73 73 65 73 4f 6e 42 61 73 65 44 69 72 65 63 74 6f 72 79 } //1 KillSameProcessesOnBaseDirectory
		$a_01_3 = {43 61 70 74 75 72 65 41 63 74 69 76 65 57 69 6e 64 6f 77 54 6f 42 61 73 65 36 34 } //1 CaptureActiveWindowToBase64
		$a_01_4 = {53 79 73 74 65 6d 4c 6f 67 67 65 72 2e 48 6f 6f 6b 69 6e 67 } //1 SystemLogger.Hooking
		$a_01_5 = {47 65 74 44 69 73 6b 53 65 72 69 61 6c 4e 75 6d 62 65 72 } //1 GetDiskSerialNumber
		$a_01_6 = {4b 65 79 62 6f 61 72 64 48 6f 6f 6b 5f 4f 6e 4b 65 79 44 6f 77 6e } //1 KeyboardHook_OnKeyDown
		$a_00_7 = {53 00 45 00 4c 00 45 00 43 00 54 00 20 00 55 00 55 00 49 00 44 00 20 00 46 00 52 00 4f 00 4d 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 43 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 53 00 79 00 73 00 74 00 65 00 6d 00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00 } //1 SELECT UUID FROM Win32_ComputerSystemProduct
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_00_7  & 1)*1) >=10
 
}