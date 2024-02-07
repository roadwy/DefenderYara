
rule Trojan_BAT_Keylogger_ABS_MTB{
	meta:
		description = "Trojan:BAT/Keylogger.ABS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 07 00 00 06 00 "
		
	strings :
		$a_01_0 = {57 3f a2 1f 09 0f 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 04 01 00 00 49 00 00 00 ae 00 00 00 b1 01 00 00 a2 01 00 00 } //01 00 
		$a_01_1 = {43 6c 69 70 62 6f 61 72 64 } //01 00  Clipboard
		$a_01_2 = {67 65 74 5f 57 6f 72 6b 69 6e 67 44 69 72 65 63 74 6f 72 79 } //01 00  get_WorkingDirectory
		$a_01_3 = {47 65 74 46 6f 6c 64 65 72 50 61 74 68 } //01 00  GetFolderPath
		$a_01_4 = {47 65 74 46 69 6c 65 44 72 6f 70 4c 69 73 74 } //01 00  GetFileDropList
		$a_01_5 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_01_6 = {67 65 74 5f 4b 65 79 62 6f 61 72 64 44 65 76 69 63 65 } //00 00  get_KeyboardDevice
	condition:
		any of ($a_*)
 
}