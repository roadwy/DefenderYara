
rule Trojan_Win64_CobaltStrike_CRTJ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CRTJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 7c 24 20 41 b9 40 00 00 00 8b d7 41 b8 00 30 00 00 33 c9 ff d0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}