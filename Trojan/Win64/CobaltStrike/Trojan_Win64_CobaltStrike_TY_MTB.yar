
rule Trojan_Win64_CobaltStrike_TY_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.TY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {b8 f7 34 c2 72 49 83 c0 01 f7 ee 2b d6 c1 fa 05 8b c2 c1 e8 1f 03 d0 48 63 c6 83 c6 01 48 63 ca 48 6b c9 3a 48 03 c8 42 0f b6 04 11 43 32 44 01 ff 41 88 40 ff 3b 74 24 20 72 c5 } //2
		$a_01_1 = {54 65 73 74 2e 64 6c 6c } //1 Test.dll
		$a_01_2 = {42 57 51 38 31 48 37 } //1 BWQ81H7
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}