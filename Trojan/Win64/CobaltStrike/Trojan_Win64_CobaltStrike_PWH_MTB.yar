
rule Trojan_Win64_CobaltStrike_PWH_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.PWH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 63 ca 0f b6 c3 42 32 04 09 2a c2 ff c2 42 88 04 01 83 fa 20 72 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}