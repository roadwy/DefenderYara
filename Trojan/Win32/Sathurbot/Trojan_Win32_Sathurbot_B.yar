
rule Trojan_Win32_Sathurbot_B{
	meta:
		description = "Trojan:Win32/Sathurbot.B,SIGNATURE_TYPE_PEHSTR_EXT,06 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {80 38 3b 0f 84 98 00 00 00 8b 07 8b 08 49 3b f1 7c d7 e9 8a 00 00 00 3c 3c 75 0e ff 35 } //1
		$a_01_1 = {5f 6d 6f 64 75 6c 65 2e 64 61 74 00 2a 2e 2a 00 44 61 74 61 5c } //1
		$a_01_2 = {69 6e 73 74 61 6c 6c 5f 6d 6f 64 75 6c 65 00 00 75 70 64 61 74 65 00 00 72 75 6e 5f 62 69 6e 61 72 79 } //1
		$a_01_3 = {6f 70 65 6e 00 00 00 00 22 00 00 00 2c 44 6c 6c 49 6e 73 74 61 6c 6c } //1
		$a_01_4 = {5c 62 6f 74 5c 73 61 74 75 72 6e } //1 \bot\saturn
		$a_01_5 = {48 79 64 72 61 4c 6f 61 64 65 72 2e 44 4c 4c } //1 HydraLoader.DLL
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}