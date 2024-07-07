
rule Trojan_Win64_CobaltStrike_CCHW_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CCHW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4c 8d 56 01 45 0f b6 59 02 45 31 c3 45 0f b6 41 01 45 31 d8 4c 39 d2 73 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win64_CobaltStrike_CCHW_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.CCHW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b 6d 00 31 c0 31 c9 31 d2 31 db eb 0f 41 83 f1 90 01 01 45 88 4c 18 ff 48 ff c0 4c 89 c1 48 3d 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}