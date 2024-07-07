
rule Trojan_Win64_CobaltStrike_ARA_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 88 45 00 49 8b c3 48 c1 f8 10 0f b6 d0 c1 f9 10 42 0f b6 84 32 20 79 00 00 32 c1 41 8b c8 } //2
		$a_01_1 = {41 0f b6 0c 00 ff c2 30 08 48 8d 40 01 3b 93 d0 03 00 00 7c eb } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}