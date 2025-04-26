
rule Trojan_Win64_CobaltStrike_ZZV_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.ZZV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 ff c0 49 63 c8 48 8d 14 24 48 03 d1 0f b6 0a 41 88 0a 44 88 0a 45 02 0a 41 0f b6 c9 0f b6 14 0c 41 30 13 49 ff c3 48 83 eb 01 75 9d } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}