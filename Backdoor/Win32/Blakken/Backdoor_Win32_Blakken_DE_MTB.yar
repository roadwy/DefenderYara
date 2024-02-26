
rule Backdoor_Win32_Blakken_DE_MTB{
	meta:
		description = "Backdoor:Win32/Blakken.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 03 00 "
		
	strings :
		$a_81_0 = {52 65 73 6f 75 72 63 65 20 4c 4f 53 41 52 63 6b 6c 45 53 } //03 00  Resource LOSARcklES
		$a_81_1 = {47 65 74 4c 6f 6e 67 50 61 74 68 4e 61 6d 65 41 } //03 00  GetLongPathNameA
		$a_81_2 = {6d 73 63 74 6c 73 5f 68 6f 74 6b 65 79 } //03 00  msctls_hotkey
		$a_81_3 = {43 6f 70 79 45 6e 68 4d 65 74 61 46 69 6c 65 41 } //03 00  CopyEnhMetaFileA
		$a_81_4 = {53 79 73 52 65 41 6c 6c 6f 63 53 74 72 69 6e 67 4c 65 6e } //03 00  SysReAllocStringLen
		$a_81_5 = {52 65 67 69 73 74 65 72 43 6c 69 70 62 6f 61 72 64 46 6f 72 6d 61 74 41 } //03 00  RegisterClipboardFormatA
		$a_81_6 = {4d 6f 74 20 64 65 20 70 61 73 73 65 } //00 00  Mot de passe
	condition:
		any of ($a_*)
 
}