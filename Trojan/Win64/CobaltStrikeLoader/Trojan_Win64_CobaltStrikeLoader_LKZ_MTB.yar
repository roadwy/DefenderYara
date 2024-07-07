
rule Trojan_Win64_CobaltStrikeLoader_LKZ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrikeLoader.LKZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 04 1f 30 03 48 ff c3 48 83 e9 01 75 90 02 20 41 b9 04 00 00 00 41 b8 00 10 00 00 49 8d 56 0a 33 c9 ff 15 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}