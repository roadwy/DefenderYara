
rule Trojan_Win32_Ninunarch_H{
	meta:
		description = "Trojan:Win32/Ninunarch.H,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_01_0 = {3a 2f 70 69 63 2f 77 69 6e 72 61 72 5f 73 6d 61 6c 6c 2e 69 63 6f } //2 :/pic/winrar_small.ico
		$a_01_1 = {38 31 30 39 35 38 30 } //2 8109580
		$a_01_2 = {6f 6e 5f 65 64 69 74 41 6e 73 77 65 72 43 6f 64 65 53 65 63 6f 6e 64 5f 74 65 78 74 43 68 61 6e 67 65 64 28 51 53 74 72 69 6e 67 29 } //3 on_editAnswerCodeSecond_textChanged(QString)
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*3) >=7
 
}