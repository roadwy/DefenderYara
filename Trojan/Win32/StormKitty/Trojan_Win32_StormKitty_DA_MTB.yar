
rule Trojan_Win32_StormKitty_DA_MTB{
	meta:
		description = "Trojan:Win32/StormKitty.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {89 14 24 89 44 24 04 89 4c 24 08 e8 ?? ?? ?? ?? 8b 44 24 0c 8b 4c 24 10 89 04 24 89 4c 24 04 e8 ?? ?? ?? ?? 8b 44 24 08 8b 4c 24 14 8b 54 24 0c 8b 5c 24 10 8b 6c 24 18 89 84 24 9c 00 00 00 89 94 24 a0 00 00 00 89 9c 24 a4 00 00 00 89 8c 24 a8 00 00 00 89 ac 24 ac 00 00 00 83 c4 7c c3 } //3
		$a_01_1 = {0f b6 34 2b 31 d6 87 de 88 1c 28 87 de 45 } //2
		$a_01_2 = {6d 61 69 6e 2e 64 6f 75 62 6c 65 44 65 63 72 79 70 74 } //2 main.doubleDecrypt
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=7
 
}