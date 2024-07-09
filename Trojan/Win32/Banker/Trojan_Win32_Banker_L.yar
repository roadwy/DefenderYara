
rule Trojan_Win32_Banker_L{
	meta:
		description = "Trojan:Win32/Banker.L,SIGNATURE_TYPE_PEHSTR_EXT,07 00 06 00 07 00 00 "
		
	strings :
		$a_02_0 = {50 8b 43 fc 03 46 fc a9 00 00 00 c0 75 ?? e8 ?? ?? ?? ?? 89 c7 89 fa 89 d8 8b 4b fc d1 e1 e8 ?? ?? ?? ?? 89 f0 8b 4e fc d1 e1 8b 53 fc d1 e2 01 fa e8 ?? ?? ?? ?? 58 89 fa 85 ff 74 ?? ff 4f f8 e8 } //1
		$a_00_1 = {70 00 72 00 61 00 71 00 75 00 65 00 6d 00 3d 00 6d 00 61 00 67 00 61 00 6f 00 78 00 78 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00 } //1 praquem=magaoxx@gmail.com
		$a_00_2 = {6d 00 61 00 67 00 61 00 6f 00 78 00 78 00 40 00 69 00 67 00 2e 00 63 00 6f 00 6d 00 2e 00 62 00 72 00 } //1 magaoxx@ig.com.br
		$a_00_3 = {77 00 77 00 77 00 2e 00 63 00 68 00 75 00 61 00 6e 00 6c 00 69 00 2e 00 63 00 6f 00 6d 00 2e 00 6d 00 79 00 } //1 www.chuanli.com.my
		$a_00_4 = {62 61 6e 63 6f } //1 banco
		$a_00_5 = {73 65 6e 68 61 } //1 senha
		$a_00_6 = {8b 44 24 04 8b 77 fc e8 4f fe ff ff 8b 7c 24 04 8b 07 89 04 24 d1 e6 03 37 4b eb 0a e8 ca f1 ff ff 89 04 24 89 c6 8b 44 9c 1c 89 f2 85 c0 74 0c 8b 48 fc d1 e1 01 ce e8 97 ce ff ff 4b 75 e7 8b 14 24 8b 44 24 04 85 ff 75 0c 85 d2 74 03 ff 4a f8 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=6
 
}