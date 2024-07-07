
rule Trojan_Win64_CobaltStrike_LO_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.LO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {41 b9 40 00 00 00 48 63 d8 41 b8 00 30 00 00 48 8b d3 33 c9 ff 15 } //1
		$a_01_1 = {b9 88 13 00 00 48 8b f8 ff 15 } //1
		$a_01_2 = {ff c8 33 d2 89 41 38 41 8b c3 f7 f3 80 c2 30 44 8b d8 80 fa 39 7e 0c 41 8a c1 34 01 c0 e0 05 04 07 02 d0 48 8b 41 48 88 10 48 ff 49 48 eb c5 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}