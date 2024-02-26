
rule Trojan_Win32_Zenpak_J_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.J!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {8a 14 1e 47 8a 0c 07 8b c6 32 d1 88 14 1e 99 f7 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Zenpak_J_MTB_2{
	meta:
		description = "Trojan:Win32/Zenpak.J!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 67 72 65 65 6e 66 6f 72 74 68 64 6d 6f 76 65 64 79 69 65 6c 64 69 6e 67 2e 4f 75 72 } //01 00  dgreenforthdmovedyielding.Our
		$a_01_1 = {48 67 69 76 65 6e 2e 75 6e 74 6f 6c 65 73 73 65 72 61 62 6f 76 65 } //01 00  Hgiven.untolesserabove
		$a_01_2 = {54 68 65 79 2e 72 65 64 61 79 74 77 6f 69 74 73 65 6c 66 44 72 79 49 52 67 } //01 00  They.redaytwoitselfDryIRg
		$a_01_3 = {50 58 35 67 6f 64 56 6f 75 72 6d 39 67 72 65 65 6e 66 72 75 69 74 } //01 00  PX5godVourm9greenfruit
		$a_01_4 = {53 65 4c 46 2e 45 78 45 } //00 00  SeLF.ExE
	condition:
		any of ($a_*)
 
}