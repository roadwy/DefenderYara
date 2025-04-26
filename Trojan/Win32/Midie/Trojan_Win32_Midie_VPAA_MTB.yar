
rule Trojan_Win32_Midie_VPAA_MTB{
	meta:
		description = "Trojan:Win32/Midie.VPAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 44 24 0c 8b 15 e4 71 00 10 03 c1 8a 14 32 30 10 46 41 3b 0f 72 e2 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}