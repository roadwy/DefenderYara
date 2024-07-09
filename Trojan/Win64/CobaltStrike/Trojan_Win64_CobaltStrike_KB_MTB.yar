
rule Trojan_Win64_CobaltStrike_KB_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.KB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {69 f8 08 02 00 00 41 b8 00 30 00 00 33 c9 8b d7 8b f7 ff 15 } //1
		$a_01_1 = {41 b8 00 30 00 00 8b 10 83 41 08 fc 89 51 14 33 c9 44 8d 49 04 ff 15 } //1
		$a_01_2 = {c5 fd 7f 41 60 c5 fd 7f 81 80 00 00 00 c5 fd 7f 81 a0 00 00 00 c5 fd 7f 81 c0 00 00 00 c5 fd 7f 81 e0 00 00 00 48 81 c1 00 01 00 00 49 81 e8 00 01 00 00 49 81 f8 00 01 00 00 73 b6 } //1
		$a_03_3 = {41 b9 00 30 00 00 4c 89 65 a0 c7 44 24 20 40 00 00 00 ff 15 ?? ?? 00 00 48 8b f8 48 85 c0 75 2b } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}