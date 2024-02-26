
rule Trojan_Win32_Remcos_GV_MTB{
	meta:
		description = "Trojan:Win32/Remcos.GV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 00 56 00 43 00 4c 00 41 00 4c } //01 00 
		$a_01_1 = {37 00 36 00 39 00 30 00 38 00 39 00 37 00 32 00 31 } //01 00 
		$a_01_2 = {57 00 48 00 41 00 4d 00 4d 00 53 00 49 00 4f 00 4e } //01 00 
		$a_81_3 = {52 54 4c 43 6f 6e 73 74 73 } //01 00  RTLConsts
		$a_81_4 = {47 65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61 } //00 00  GetClipboardData
	condition:
		any of ($a_*)
 
}