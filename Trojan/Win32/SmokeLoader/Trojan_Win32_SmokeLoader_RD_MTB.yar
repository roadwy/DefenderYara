
rule Trojan_Win32_SmokeLoader_RD_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b d0 c1 ea 05 03 54 24 24 03 c5 33 d1 33 d0 2b fa 8b cf c1 e1 04 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}