
rule Trojan_Win64_CobaltStrike_YAK_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.YAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 ff c9 e9 90 0a 05 00 48 ff c9 90 13 90 13 ac 90 13 32 c3 90 13 02 c3 90 13 32 c3 90 13 c0 c8 ca 90 13 aa 90 13 48 ff c9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}