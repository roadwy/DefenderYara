
rule Spammer_Win32_Emotet_C{
	meta:
		description = "Spammer:Win32/Emotet.C,SIGNATURE_TYPE_PEHSTR_EXT,79 00 79 00 05 00 00 "
		
	strings :
		$a_01_0 = {0f b6 4d 0b 8d 34 01 8a 16 00 55 ff 0f b6 4d ff 03 c8 8a 19 fe 45 0b 88 1e 88 11 8b 4d 0c 0f b6 d2 0f b6 f3 03 f2 81 e6 ff 00 00 00 8a 14 06 03 cf 30 11 47 3b 7d 10 72 c7 } //100
		$a_01_1 = {41 76 20 73 74 61 74 69 63 20 65 6e 74 72 6f 70 79 20 4d 69 63 72 6f 73 6f 66 74 20 45 73 73 65 6e 74 69 61 6c 20 2e 2e 2e 2e 20 6f 68 20 6f 68 20 6f 68 } //100 Av static entropy Microsoft Essential .... oh oh oh
		$a_01_2 = {22 00 25 00 73 00 22 00 20 00 2f 00 63 00 20 00 22 00 25 00 73 00 22 00 } //10 "%s" /c "%s"
		$a_01_3 = {43 00 6f 00 6d 00 53 00 70 00 65 00 63 00 } //10 ComSpec
		$a_01_4 = {25 66 72 6f 6d 5f 65 6d 61 69 6c 25 } //1 %from_email%
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*100+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*1) >=121
 
}