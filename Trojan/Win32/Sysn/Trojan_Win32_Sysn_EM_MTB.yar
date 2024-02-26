
rule Trojan_Win32_Sysn_EM_MTB{
	meta:
		description = "Trojan:Win32/Sysn.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {42 72 75 74 74 65 72 20 73 77 69 70 79 20 75 6e 61 63 65 5c 54 72 61 63 69 6e 67 5c 47 6f 62 69 65 } //01 00  Brutter swipy unace\Tracing\Gobie
		$a_81_1 = {53 75 62 46 6f 6c 64 65 72 4e 61 6d 65 5c 51 75 6f 74 61 74 69 6f 6e 2e 73 63 72 } //01 00  SubFolderName\Quotation.scr
		$a_81_2 = {56 42 2e 43 6c 69 70 62 6f 61 72 64 } //01 00  VB.Clipboard
		$a_81_3 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //01 00  WriteProcessMemory
		$a_81_4 = {41 62 61 74 61 67 65 2e 4d 65 61 6c 62 65 72 72 } //00 00  Abatage.Mealberr
	condition:
		any of ($a_*)
 
}