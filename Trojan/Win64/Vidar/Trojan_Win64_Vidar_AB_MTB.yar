
rule Trojan_Win64_Vidar_AB_MTB{
	meta:
		description = "Trojan:Win64/Vidar.AB!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b d0 8b c8 c1 ea 05 03 54 24 28 c1 e1 04 03 4c 24 2c 03 c7 33 d1 33 d0 2b f2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}