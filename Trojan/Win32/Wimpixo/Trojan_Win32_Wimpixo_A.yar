
rule Trojan_Win32_Wimpixo_A{
	meta:
		description = "Trojan:Win32/Wimpixo.A,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 44 24 0c 56 8b 74 24 0c 2b f0 33 d2 8a d5 32 10 88 14 06 66 0f b6 10 03 d1 b9 bf 58 00 00 69 d2 93 31 00 00 2b ca 40 4f 75 e0 } //5
		$a_01_1 = {d1 e8 89 45 e8 74 4a 8b 45 08 66 8b 00 8b d8 66 81 e3 00 f0 66 81 fb 00 30 75 25 25 ff 0f 00 00 ff 45 f4 03 01 8b 1c 30 2b 5f 1c 3b 5d 0c 75 10 0f b7 5c 30 fe 83 eb 4f 81 fb 78 05 00 00 74 15 ff 45 fc 83 45 08 02 8b 45 fc 3b 45 e8 72 b8 } //5
		$a_01_2 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 25 73 00 } //1
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1) >=11
 
}