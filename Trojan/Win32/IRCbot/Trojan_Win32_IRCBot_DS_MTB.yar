
rule Trojan_Win32_IRCBot_DS_MTB{
	meta:
		description = "Trojan:Win32/IRCBot.DS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {ac 53 56 57 33 c9 89 4d ac 89 4d b0 89 4d b8 89 4d b4 89 4d bc 89 4d ec 89 55 f8 89 45 fc 8b 45 f8 e8 99 a5 ff ff 33 c0 55 68 09 9f 40 00 64 ff 30 64 89 20 33 c0 89 45 f4 8b 45 fc ff 70 14 68 24 9f 40 } //1
		$a_01_1 = {33 c0 89 45 d0 8b 45 f8 e8 67 a5 ff ff 89 45 d4 33 c0 89 45 dc 8b 45 ec e8 57 a3 ff ff 50 8b 45 ec e8 4e a5 ff ff 50 6a 00 e8 ba ae ff ff 50 e8 ac ae ff ff e8 0b fd ff ff 85 c0 74 0c 66 b8 03 00 66 c7 45 f2 03 } //1
		$a_01_2 = {83 c4 f0 8b d8 33 ed 33 ff 8d 43 10 e8 7b 9b ff ff 83 fd 01 1b c0 40 3c 01 75 4a 8b 43 10 ba d8 a3 40 00 e8 28 9f ff ff 75 0a 8d 43 10 e8 5a 9b ff ff eb 39 8b 43 10 ba e4 a3 40 00 e8 0f 9f ff ff 75 0d 8d 43 10 ba d8 a3 40 } //1
		$a_01_3 = {a1 70 b1 40 00 ff 00 66 c7 04 24 02 00 68 bd 01 00 00 e8 6e a9 ff ff 66 89 44 24 02 8b 43 10 e8 19 9f ff ff 50 e8 63 a9 ff ff 89 44 24 04 6a 10 8d 44 24 04 50 56 e8 42 a9 } //1
		$a_01_4 = {68 d7 75 00 00 e8 2b a9 ff ff 66 89 44 24 02 8b 43 10 e8 d6 9e ff ff 50 e8 20 a9 ff ff 89 44 24 04 6a 10 8d 44 24 04 50 56 e8 ff a8 ff ff 40 74 05 83 cf ff eb 07 a1 70 b1 40 00 ff 00 85 ff 74 1f 56 e8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}