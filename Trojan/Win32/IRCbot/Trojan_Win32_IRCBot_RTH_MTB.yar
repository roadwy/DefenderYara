
rule Trojan_Win32_IRCBot_RTH_MTB{
	meta:
		description = "Trojan:Win32/IRCBot.RTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_02_0 = {68 ec 09 71 00 5e 4f e8 ?? ?? ?? ?? 29 df 4b 21 df 31 30 09 fb bf df 93 9e 8c 81 c0 01 00 00 00 29 fb 83 ec 04 89 3c 24 5f 81 c3 74 c0 53 5c 39 c8 75 } //2
		$a_02_1 = {bf 2e ce 43 00 21 c0 e8 ?? ?? ?? ?? 09 c3 b8 c4 9c da 43 31 3e 81 e8 50 cd 61 97 29 db 81 c6 01 00 00 00 39 ce 75 } //2
		$a_02_2 = {68 2e ce 43 00 5b 21 f1 e8 ?? ?? ?? ?? 01 f1 31 1a 89 ce 29 f6 42 39 fa 75 } //2
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2+(#a_02_2  & 1)*2) >=2
 
}
rule Trojan_Win32_IRCBot_RTH_MTB_2{
	meta:
		description = "Trojan:Win32/IRCBot.RTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 07 00 00 "
		
	strings :
		$a_03_0 = {83 c4 04 29 c1 21 c0 e8 ?? ?? ?? ?? 40 31 1e 29 c1 46 68 bd 85 49 2a 59 29 c1 39 fe 75 } //1
		$a_03_1 = {be 6f 48 4f 00 21 d7 21 ff 29 d2 e8 ?? ?? ?? ?? 29 ff 31 31 83 ec 04 89 14 24 5a 89 ff 81 ef 01 00 00 00 81 c1 01 00 00 00 42 39 c1 75 } //1
		$a_03_2 = {5e 01 c0 e8 ?? ?? ?? ?? 49 81 c0 01 00 00 00 31 33 01 c8 81 c0 13 e4 c1 1b 43 09 c1 81 c1 1b 60 54 2c 39 fb 75 } //1
		$a_03_3 = {81 ee 7c 9a fa cf e8 ?? ?? ?? ?? 81 ee 48 d7 01 a4 09 f0 81 c0 19 5f 25 e5 31 1f 01 f6 21 f6 68 b6 ca b8 7b 5e 81 c7 01 00 00 00 21 f6 29 f0 4e 39 d7 75 } //1
		$a_03_4 = {be 6f 48 4f 00 29 cb e8 ?? ?? ?? ?? 81 c3 d9 02 5d dc 81 c1 f5 66 ab b6 31 37 49 49 81 c7 01 00 00 00 21 d9 b9 11 c1 aa 1d 39 c7 75 } //1
		$a_00_5 = {09 d7 09 ff 21 d2 21 d7 42 31 0b f7 d2 81 c2 01 00 00 00 81 c3 02 00 00 00 4f bf 9f f7 75 93 09 d7 39 f3 0f } //1
		$a_00_6 = {09 d7 09 ff 21 d2 21 d7 42 31 0b f7 d2 81 c2 01 00 00 00 81 c3 02 00 00 00 4f bf 9f f7 75 93 09 d7 39 f3 0f 8c } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=1
 
}