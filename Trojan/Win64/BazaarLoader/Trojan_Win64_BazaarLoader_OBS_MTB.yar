
rule Trojan_Win64_BazaarLoader_OBS_MTB{
	meta:
		description = "Trojan:Win64/BazaarLoader.OBS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 44 24 30 48 8b 00 8b 40 28 48 8b 4c 24 40 48 03 c8 48 8b c1 48 89 84 24 a0 00 00 00 45 33 c0 ba 01 00 00 00 48 b9 00 00 00 80 01 00 00 00 ff 94 24 a0 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}