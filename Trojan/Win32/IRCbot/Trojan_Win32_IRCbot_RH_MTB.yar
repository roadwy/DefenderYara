
rule Trojan_Win32_IRCbot_RH_MTB{
	meta:
		description = "Trojan:Win32/IRCbot.RH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_02_0 = {bb ec 09 71 00 89 c9 e8 ?? ?? ?? ?? 81 c6 aa d6 39 c6 31 1f 01 f1 29 c9 81 c7 01 00 00 00 29 f6 be c7 ea 7b e9 4e 39 d7 75 } //2
		$a_02_1 = {29 f7 09 f6 09 f6 e8 ?? ?? ?? ?? 01 f7 57 5e 31 03 4e 29 f6 21 fe 43 56 5e 46 01 ff 39 d3 75 } //2
		$a_02_2 = {8b 34 24 83 c4 04 81 c0 59 e8 51 6f 81 e8 01 00 00 00 e8 ?? ?? ?? ?? 29 ff 29 ff bf 0c 21 db f0 31 33 81 ef ba 94 b0 47 43 21 f8 39 cb 75 } //2
		$a_02_3 = {81 c1 3c fe 02 05 e8 ?? ?? ?? ?? 56 5e 81 c6 01 00 00 00 31 07 81 c6 0a 7b 7d b6 47 46 41 68 5a e5 fc 78 5e 39 d7 75 } //2
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2+(#a_02_2  & 1)*2+(#a_02_3  & 1)*2) >=2
 
}
rule Trojan_Win32_IRCbot_RH_MTB_2{
	meta:
		description = "Trojan:Win32/IRCbot.RH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_02_0 = {ba 14 8a 43 00 21 ff e8 ?? ?? ?? ?? 81 ef cf 4b d1 69 81 ef 01 00 00 00 81 ef f2 d2 ee 1f 31 16 81 c7 d0 06 5e b1 89 fb 46 4f 39 c6 75 d2 } //2
		$a_02_1 = {be ec 09 71 00 81 c0 74 cc d7 b2 e8 ?? ?? ?? ?? 50 5a 31 37 81 e8 f0 a7 61 26 81 e8 a2 19 5d 28 81 c7 01 00 00 00 81 e8 15 85 63 d7 21 c2 b8 e1 b9 5b 11 39 df 75 } //2
		$a_02_2 = {bb ec 09 71 00 81 c6 43 47 95 62 e8 ?? ?? ?? ?? 01 d2 09 f6 81 c2 01 00 00 00 31 19 81 ea 01 c7 c1 a2 42 81 c1 01 00 00 00 21 f6 29 d2 29 d2 39 f9 75 } //2
		$a_02_3 = {bb ec 09 71 00 09 c9 e8 ?? ?? ?? ?? 81 c2 69 3c 85 d7 31 1f 01 d1 68 bb be a9 2c 59 01 d2 81 c7 01 00 00 00 89 d1 09 c9 ba 13 a3 23 1c 39 c7 75 } //2
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2+(#a_02_2  & 1)*2+(#a_02_3  & 1)*2) >=2
 
}