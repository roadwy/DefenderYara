
rule Trojan_Win64_CobaltStrikeLoader_LK_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrikeLoader.LK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b d8 48 85 c0 74 10 ba e8 03 00 00 48 8b cb ff 15 90 01 02 00 00 eb f0 48 83 c4 20 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}