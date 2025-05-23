
rule Trojan_Win32_IRCBot_RTU_MTB{
	meta:
		description = "Trojan:Win32/IRCBot.RTU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 07 00 00 "
		
	strings :
		$a_02_0 = {be ec 09 71 00 29 db e8 ?? ?? ?? ?? 81 ea 01 00 00 00 4a 09 d3 31 37 81 eb a0 3c a3 7b 81 c7 01 00 00 00 21 d3 39 cf 75 } //1
		$a_02_1 = {b9 ec 09 71 00 09 f7 01 f7 e8 ?? ?? ?? ?? 4e 81 c6 f8 d6 97 9c 89 fe 31 0a 09 f7 47 42 46 29 f7 29 fe 39 c2 75 } //1
		$a_02_2 = {b9 2e ce 43 00 e8 ?? ?? ?? ?? 31 0b 81 c6 01 00 00 00 81 c3 01 00 00 00 89 f6 09 c0 39 d3 75 } //1
		$a_02_3 = {81 ef f0 e1 f4 4b bf 29 1c 4a 58 e8 ?? ?? ?? ?? 21 f8 29 ff 31 11 01 c7 09 ff 41 83 ec 04 89 04 24 58 bf 4e 7e d4 fc 39 f1 75 } //1
		$a_02_4 = {83 ec 04 c7 04 24 2e ce 43 00 8b 0c 24 83 c4 04 21 f7 e8 ?? ?? ?? ?? 31 0a 46 4f 42 bf 03 d1 e2 c6 29 fe 39 da 75 } //1
		$a_02_5 = {83 ec 04 c7 04 24 2e ce 43 00 8b 0c 24 83 c4 04 e8 ?? ?? ?? ?? be 9a cd 63 f4 31 08 40 46 81 ee 7b 8a 00 9d 39 d8 75 } //1
		$a_02_6 = {ba da cc 43 00 89 f6 e8 ?? ?? ?? ?? 89 ff 01 fe 31 13 21 f7 43 39 cb 75 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1+(#a_02_4  & 1)*1+(#a_02_5  & 1)*1+(#a_02_6  & 1)*1) >=1
 
}