
rule Trojan_Win64_CobaltStrike_YAI_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.YAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff cf 81 cf 90 01 04 ff c7 48 63 cf 48 8d 54 24 40 48 03 d1 0f b6 0a 41 88 08 44 88 0a 41 0f b6 10 49 03 d1 0f b6 ca 0f b6 54 0c 40 41 30 12 49 ff c2 49 83 eb 01 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}