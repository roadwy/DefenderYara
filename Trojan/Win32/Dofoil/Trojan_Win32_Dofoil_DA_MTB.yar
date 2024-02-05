
rule Trojan_Win32_Dofoil_DA_MTB{
	meta:
		description = "Trojan:Win32/Dofoil.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {66 81 e1 f1 22 66 89 8c 24 90 01 04 8b 94 24 90 01 04 8b b4 24 90 01 04 66 89 84 24 90 01 04 8a 1c 16 8b 94 24 90 01 04 8b b4 24 90 01 04 88 1c 16 66 8b 84 24 90 01 04 66 35 1a 1e 66 89 84 24 90 01 04 8b 8c 24 90 01 04 8b 54 24 90 01 01 01 d1 89 8c 24 90 01 04 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}