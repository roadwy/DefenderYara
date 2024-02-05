
rule Trojan_Win32_Cosmu_ARA_MTB{
	meta:
		description = "Trojan:Win32/Cosmu.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {bb 00 00 00 00 8a 9a 3f 29 40 00 80 fb 98 75 08 90 01 01 b8 00 00 00 00 90 01 02 80 fb b0 90 01 18 75 0a 90 01 05 b8 91 00 00 00 08 c3 90 01 10 c1 e3 03 be 3f 21 40 00 01 de 90 01 07 89 d3 90 01 05 c1 e3 03 90 01 0f 8b 3d 04 10 40 00 90 01 04 01 df b9 08 00 00 00 90 01 01 f3 a4 90 01 07 42 90 01 1e 81 fa a9 54 00 00 90 01 17 0f 85 28 ff ff ff 90 00 } //01 00 
		$a_01_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //00 00 
	condition:
		any of ($a_*)
 
}