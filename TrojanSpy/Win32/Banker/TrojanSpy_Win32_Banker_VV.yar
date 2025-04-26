
rule TrojanSpy_Win32_Banker_VV{
	meta:
		description = "TrojanSpy:Win32/Banker.VV,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {8b 4b 70 ba ?? ?? ?? ?? 8b c6 e8 ee d3 ff ff dd 43 40 d8 1d ?? ?? ?? ?? df e0 9e 76 1f ff 73 44 ff 73 40 8d 55 f8 33 c0 e8 00 62 ff ff 8b 4d f8 ba ?? ?? ?? ?? 8b c6 e8 c1 d3 ff ff 8b 7b 20 85 ff 75 0a 83 7b 1c 00 0f 84 88 00 00 00 83 7b 1c 00 } //2
		$a_00_1 = {4b 65 79 6c 6f 67 67 65 72 20 6f 66 20 42 61 6e 6b 65 72 } //1 Keylogger of Banker
		$a_00_2 = {4b 65 79 6c 6f 67 67 65 72 5f 50 61 79 50 61 6c } //1 Keylogger_PayPal
		$a_00_3 = {78 2d 63 6f 64 65 72 2d 78 } //1 x-coder-x
		$a_00_4 = {53 65 6e 68 61 } //1 Senha
		$a_00_5 = {44 65 76 69 63 65 5c 76 61 72 73 61 6f } //1 Device\varsao
	condition:
		((#a_03_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}