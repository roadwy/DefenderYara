
rule Trojan_Win64_CobaltStrike_PSS_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.PSS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 c9 44 8b c3 48 8b d7 ff 15 9a 49 04 00 } //1
		$a_03_1 = {41 f7 e9 c1 fa 04 8b c2 c1 e8 90 01 01 03 d0 41 8b c1 41 ff c1 6b d2 42 2b c2 48 63 c8 48 8d 05 10 93 04 00 8a 04 01 43 32 04 10 41 88 02 49 ff c2 44 3b cf 72 c7 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}