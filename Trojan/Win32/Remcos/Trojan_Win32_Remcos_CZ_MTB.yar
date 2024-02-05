
rule Trojan_Win32_Remcos_CZ_MTB{
	meta:
		description = "Trojan:Win32/Remcos.CZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {8a c8 66 be 48 11 bb 90 01 04 d3 c3 8d b4 05 ec fe ff ff c1 d1 90 01 01 8d 0c 18 f9 32 0c 37 88 0e 0f 90 00 } //03 00 
		$a_81_1 = {47 6c 6f 62 61 6c 4c 6f 63 6b } //02 00 
		$a_81_2 = {4f 70 65 6e 43 6c 69 70 62 6f 61 72 64 } //00 00 
	condition:
		any of ($a_*)
 
}