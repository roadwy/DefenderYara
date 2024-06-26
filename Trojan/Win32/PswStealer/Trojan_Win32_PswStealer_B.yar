
rule Trojan_Win32_PswStealer_B{
	meta:
		description = "Trojan:Win32/PswStealer.B,SIGNATURE_TYPE_CMDHSTR_EXT,ffffffe8 03 6f 00 08 00 00 64 00 "
		
	strings :
		$a_00_0 = {70 00 61 00 73 00 73 00 2a 00 } //64 00  pass*
		$a_00_1 = {70 00 61 00 73 00 73 00 77 00 2a 00 } //64 00  passw*
		$a_00_2 = {70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 } //64 00  password
		$a_00_3 = {70 00 73 00 77 00 2a 00 } //0a 00  psw*
		$a_00_4 = {47 00 65 00 74 00 2d 00 43 00 68 00 69 00 6c 00 64 00 49 00 74 00 65 00 6d 00 } //01 00  Get-ChildItem
		$a_00_5 = {53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 45 00 6e 00 76 00 69 00 72 00 6f 00 6e 00 6d 00 65 00 6e 00 74 00 2b 00 53 00 70 00 65 00 63 00 69 00 61 00 6c 00 46 00 6f 00 6c 00 64 00 65 00 72 00 } //01 00  System.Environment+SpecialFolder
		$a_00_6 = {44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 } //01 00  Desktop
		$a_00_7 = {4d 00 79 00 44 00 6f 00 63 00 75 00 6d 00 65 00 6e 00 74 00 73 00 } //00 00  MyDocuments
	condition:
		any of ($a_*)
 
}