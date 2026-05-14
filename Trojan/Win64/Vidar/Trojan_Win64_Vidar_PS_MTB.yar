
rule Trojan_Win64_Vidar_PS_MTB{
	meta:
		description = "Trojan:Win64/Vidar.PS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 04 24 48 89 44 24 08 33 d2 8b 04 24 f7 74 24 38 8b c2 8b c0 48 8b 4c 24 30 0f b6 04 01 48 8b 4c 24 20 48 8b 54 24 08 0f b6 0c 11 33 c8 8b c1 8b 0c 24 48 8b 54 24 20 88 04 0a eb b2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}