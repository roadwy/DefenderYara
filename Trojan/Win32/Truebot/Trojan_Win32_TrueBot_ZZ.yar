
rule Trojan_Win32_TrueBot_ZZ{
	meta:
		description = "Trojan:Win32/TrueBot.ZZ,SIGNATURE_TYPE_PEHSTR_EXT,ffffff91 01 ffffff91 01 05 00 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //1
		$a_01_1 = {6e 3d 25 73 26 6f 3d 25 73 26 61 3d 25 64 26 75 3d 25 73 26 70 3d 25 73 26 64 3d 25 73 } //100 n=%s&o=%s&a=%d&u=%s&p=%s&d=%s
		$a_03_2 = {8d 45 fc 50 6a 64 6a 00 90 03 01 02 e8 ff 15 90 00 } //100
		$a_03_3 = {8b 55 fc 52 8b 4a 10 8b 42 0c 89 85 90 01 01 ff ff ff 89 8d 90 01 01 ff ff ff 90 03 01 02 e8 ff 15 90 00 } //100
		$a_03_4 = {68 18 01 00 00 8d 85 90 01 01 fe ff ff 6a 00 50 e8 90 00 } //100
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*100+(#a_03_2  & 1)*100+(#a_03_3  & 1)*100+(#a_03_4  & 1)*100) >=401
 
}