
rule Trojan_BAT_SpySnake_MAM_MTB{
	meta:
		description = "Trojan:BAT/SpySnake.MAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_03_0 = {06 16 6f 43 00 00 0a 00 72 2d 00 00 70 28 44 00 00 0a 26 28 45 00 00 0a 00 2a 90 0a 30 00 28 06 00 00 06 6f 42 00 00 0a 72 2d 00 00 70 90 00 } //01 00 
		$a_01_1 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 54 00 65 00 6d 00 70 00 5c 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 2e 00 76 00 62 00 73 00 } //01 00  Windows\Temp\Software.vbs
		$a_01_2 = {57 72 69 74 65 41 6c 6c 42 79 74 65 73 } //01 00  WriteAllBytes
		$a_01_3 = {43 72 65 61 74 65 5f 5f 49 6e 73 74 61 6e 63 65 } //01 00  Create__Instance
		$a_01_4 = {67 65 74 5f 76 62 73 } //01 00  get_vbs
		$a_01_5 = {73 65 74 5f 53 68 75 74 64 6f 77 6e 53 74 79 6c 65 } //01 00  set_ShutdownStyle
		$a_01_6 = {43 68 65 63 6b 46 6f 72 53 79 6e 63 4c 6f 63 6b 4f 6e 56 61 6c 75 65 54 79 70 65 } //01 00  CheckForSyncLockOnValueType
		$a_01_7 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //00 00  DebuggableAttribute
	condition:
		any of ($a_*)
 
}