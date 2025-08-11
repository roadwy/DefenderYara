
rule Trojan_BAT_Convagent_NG_MTB{
	meta:
		description = "Trojan:BAT/Convagent.NG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0a 00 00 "
		
	strings :
		$a_01_0 = {42 65 65 6e 64 65 74 20 73 69 63 68 20 73 65 6c 62 73 74 20 6f 68 6e 65 20 42 65 6e 75 74 7a 65 72 62 65 6e 61 63 68 72 69 63 68 74 69 67 75 6e 67 } //1 Beendet sich selbst ohne Benutzerbenachrichtigung
		$a_01_1 = {57 69 6e 64 6f 77 73 20 45 72 72 6f 72 20 52 65 70 6f 72 74 69 6e 67 20 64 65 61 6b 74 69 76 69 65 72 65 6e } //1 Windows Error Reporting deaktivieren
		$a_01_2 = {57 69 6e 64 6f 77 73 20 53 65 63 75 72 69 74 79 20 4e 6f 74 69 66 69 63 61 74 69 6f 6e 73 20 64 65 61 6b 74 69 76 69 65 72 65 6e } //1 Windows Security Notifications deaktivieren
		$a_01_3 = {44 69 73 61 62 6c 65 57 69 6e 64 6f 77 73 55 70 64 61 74 65 41 63 63 65 73 73 } //1 DisableWindowsUpdateAccess
		$a_01_4 = {44 69 73 61 62 6c 65 41 6e 74 69 53 70 79 77 61 72 65 } //1 DisableAntiSpyware
		$a_01_5 = {57 69 6e 64 6f 77 53 74 79 6c 65 20 48 69 64 64 65 6e 20 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 42 79 70 61 73 73 20 2d 46 69 6c 65 } //2 WindowStyle Hidden -ExecutionPolicy Bypass -File
		$a_01_6 = {44 69 73 61 62 6c 65 52 65 61 6c 74 69 6d 65 4d 6f 6e 69 74 6f 72 69 6e 67 20 24 74 72 75 65 } //1 DisableRealtimeMonitoring $true
		$a_01_7 = {44 69 73 61 62 6c 65 49 4f 41 56 50 72 6f 74 65 63 74 69 6f 6e 20 24 74 72 75 65 } //1 DisableIOAVProtection $true
		$a_01_8 = {44 69 73 61 62 6c 65 53 63 72 69 70 74 53 63 61 6e 6e 69 6e 67 20 24 74 72 75 65 } //1 DisableScriptScanning $true
		$a_01_9 = {53 74 6f 70 2d 53 65 72 76 69 63 65 20 57 69 6e 44 65 66 65 6e 64 20 2d 46 6f 72 63 65 } //1 Stop-Service WinDefend -Force
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*2+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=11
 
}