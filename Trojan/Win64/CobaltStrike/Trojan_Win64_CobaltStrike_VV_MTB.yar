
rule Trojan_Win64_CobaltStrike_VV_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.VV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b c3 48 ff c3 83 e0 03 42 8a 04 30 30 06 48 ff c6 48 ff c9 75 e9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}