
rule Trojan_Win32_Zload_E_MTB{
	meta:
		description = "Trojan:Win32/Zload.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 6c 24 10 8b 55 00 83 44 24 10 04 81 c2 90 01 04 89 55 00 83 6c 24 14 01 75 a7 90 00 } //01 00 
		$a_00_1 = {62 72 65 61 64 5c 65 78 63 69 74 65 5c 53 74 6f 72 79 62 6f 6e 65 2e 70 64 62 } //00 00  bread\excite\Storybone.pdb
	condition:
		any of ($a_*)
 
}