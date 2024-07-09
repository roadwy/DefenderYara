
rule Trojan_Win32_Vkhost_E{
	meta:
		description = "Trojan:Win32/Vkhost.E,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 05 00 00 "
		
	strings :
		$a_03_0 = {be 99 b7 00 00 33 d2 8d 85 ?? ?? ?? ?? e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 4e 75 e6 } //10
		$a_01_1 = {2c 20 6c 69 76 65 69 6e 74 65 72 6e 65 74 2e 72 75 } //1 , liveinternet.ru
		$a_01_2 = {2c 20 6f 64 6e 6f 6b 6c 61 73 73 6e 69 6b 69 2e 72 75 } //1 , odnoklassniki.ru
		$a_01_3 = {2c 20 76 69 72 75 73 62 75 73 74 65 72 2e 68 75 } //1 , virusbuster.hu
		$a_01_4 = {2c 20 67 6f 2e 6d 61 69 6c 2e 72 75 } //1 , go.mail.ru
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=12
 
}