
rule Trojan_Win32_SpySnake_MR_MTB{
	meta:
		description = "Trojan:Win32/SpySnake.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {ff d7 8b 55 10 6a 00 8d 4d fc 51 53 8b f8 57 52 ff 15 94 d0 40 } //5
		$a_03_1 = {8a 04 37 2c 60 34 af 2c 53 34 bd 04 52 88 04 37 46 3b f3 72 ?? 6a 00 6a 00 6a 02 57 ff 15 } //3
		$a_03_2 = {8a 04 37 2c 45 34 8e fe c8 34 fd 04 73 88 04 37 46 3b f3 72 ?? 6a 00 6a 00 6a 02 57 ff 15 } //3
		$a_03_3 = {8a 04 37 2c 52 34 b8 2c 31 34 f4 2c 45 34 1f fe c0 34 ba fe c0 88 04 37 46 3b f3 72 ?? 6a 00 6a 00 6a 02 57 ff 15 } //3
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*3+(#a_03_2  & 1)*3+(#a_03_3  & 1)*3) >=8
 
}