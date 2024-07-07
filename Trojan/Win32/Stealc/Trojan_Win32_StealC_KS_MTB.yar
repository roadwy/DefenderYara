
rule Trojan_Win32_StealC_KS_MTB{
	meta:
		description = "Trojan:Win32/StealC.KS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 c1 89 54 24 18 89 44 24 10 89 1d a4 67 7b 00 8b 44 24 18 01 05 a4 67 7b 00 8b 15 a4 67 7b 00 89 54 24 30 89 5c 24 18 8b 44 24 30 01 44 24 18 8b 44 24 10 33 44 24 18 89 44 24 18 8b 44 24 18 89 44 24 18 8b 44 24 18 29 44 24 14 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}