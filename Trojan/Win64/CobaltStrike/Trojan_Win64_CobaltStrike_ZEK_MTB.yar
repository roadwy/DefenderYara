
rule Trojan_Win64_CobaltStrike_ZEK_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.ZEK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 ff c3 49 ff c1 41 f7 e3 2b ca 41 8b c3 41 ff c3 d1 e9 03 ca c1 e9 06 6b c9 75 2b c1 44 3b df 42 0f b6 04 00 88 43 ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}