
rule Trojan_Win64_CobaltStrike_GVD_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.GVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 03 c8 0f b6 01 41 88 04 38 44 88 09 41 0f b6 0c 38 49 03 c9 0f b6 c1 0f b6 4c 04 20 30 4d 00 48 ff c5 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}