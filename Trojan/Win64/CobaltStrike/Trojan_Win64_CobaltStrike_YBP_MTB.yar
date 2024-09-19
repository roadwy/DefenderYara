
rule Trojan_Win64_CobaltStrike_YBP_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.YBP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {42 0f b7 34 27 42 88 34 3f 46 88 0c 27 41 01 f1 45 0f b6 c9 46 8a 0c 0f 45 30 08 49 ff c0 49 39 c0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}