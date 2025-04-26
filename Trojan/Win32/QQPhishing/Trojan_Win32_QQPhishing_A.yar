
rule Trojan_Win32_QQPhishing_A{
	meta:
		description = "Trojan:Win32/QQPhishing.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {8b 49 0c 8a 14 19 f6 d2 88 14 01 8b 85 ?? ?? ?? ?? 03 c7 0f 80 ?? ?? ?? ?? 8b f8 e9 } //3
		$a_01_1 = {9c 90 8a 91 8b 8a 8d 93 c2 97 8b 8b 8f c5 d0 d0 } //2
		$a_01_2 = {8f 90 8f 8a 8d 93 c2 97 8b 8b 8f c5 d0 d0 } //2
		$a_00_3 = {51 51 50 6f 70 2e 63 53 79 73 54 72 61 79 } //1 QQPop.cSysTray
		$a_00_4 = {23 00 51 00 51 00 55 00 73 00 65 00 72 00 23 00 } //1 #QQUser#
		$a_00_5 = {63 00 6f 00 75 00 6e 00 74 00 75 00 72 00 6c 00 } //1 counturl
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}