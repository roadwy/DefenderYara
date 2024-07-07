
rule Trojan_Win32_Zusy_SPH_MTB{
	meta:
		description = "Trojan:Win32/Zusy.SPH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 14 0e 32 54 24 0c 66 d1 6c 24 0c 83 e0 01 85 c0 8b 44 24 0c 88 11 74 09 35 90 01 04 89 44 24 0c 83 c1 01 83 ef 01 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}