
rule Trojan_Win32_Ramdo_F{
	meta:
		description = "Trojan:Win32/Ramdo.F,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {7d 28 0f b7 4d f8 8b 55 fc 8b 42 04 0f be 0c 08 8b 55 fc 0f b6 02 33 c8 0f b7 55 f8 33 ca 0f b7 45 f8 8b 55 0c 88 0c 02 eb bd } //1
		$a_01_1 = {81 7d f4 39 e8 ab f5 74 09 81 7d f4 27 34 f0 c5 75 12 } //2
		$a_01_2 = {68 3e dd ef 6c 6a 03 6a 00 e8 } //1
		$a_01_3 = {68 27 a8 02 84 6a 03 6a 00 e8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}