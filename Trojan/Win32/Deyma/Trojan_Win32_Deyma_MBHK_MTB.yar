
rule Trojan_Win32_Deyma_MBHK_MTB{
	meta:
		description = "Trojan:Win32/Deyma.MBHK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e8 05 03 44 24 24 89 2d 90 01 04 33 c1 8b 4c 24 90 01 01 03 ce 33 c1 2b f8 8b d7 c1 e2 90 00 } //01 00 
		$a_01_1 = {54 00 4e 00 65 00 7a 00 6f 00 76 00 69 00 64 00 61 00 66 00 69 00 77 00 69 00 20 00 67 00 6f 00 7a 00 61 00 67 00 65 } //00 00 
	condition:
		any of ($a_*)
 
}