
rule Trojan_Win32_Qakbot_BV_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.BV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 4d 47 46 4c 54 5f 49 6e 69 74 44 44 45 45 6e 68 61 6e 63 65 } //01 00  UMGFLT_InitDDEEnhance
		$a_01_1 = {55 4d 47 46 4c 54 5f 43 6c 6f 73 65 44 44 45 43 6f 6c 6f 72 } //01 00  UMGFLT_CloseDDEColor
		$a_01_2 = {55 4d 47 46 4c 54 5f 43 6c 6f 73 65 4d 6f 69 72 65 } //01 00  UMGFLT_CloseMoire
		$a_01_3 = {55 4d 47 46 4c 54 5f 49 6e 69 74 4d 6f 69 72 65 } //01 00  UMGFLT_InitMoire
		$a_01_4 = {55 4d 47 46 4c 54 5f 43 6c 6f 73 65 52 65 73 69 7a 65 } //01 00  UMGFLT_CloseResize
		$a_01_5 = {55 4d 47 46 4c 54 5f 49 6e 69 74 46 6f 63 75 73 } //01 00  UMGFLT_InitFocus
		$a_01_6 = {55 4d 47 46 4c 54 5f 43 6c 6f 73 65 44 44 45 42 69 6e } //01 00  UMGFLT_CloseDDEBin
		$a_01_7 = {55 4d 47 46 4c 54 5f 49 6e 69 74 44 44 45 43 6f 6c 6f 72 } //00 00  UMGFLT_InitDDEColor
	condition:
		any of ($a_*)
 
}