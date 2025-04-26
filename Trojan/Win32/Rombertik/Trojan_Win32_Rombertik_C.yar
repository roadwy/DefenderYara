
rule Trojan_Win32_Rombertik_C{
	meta:
		description = "Trojan:Win32/Rombertik.C,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {84 d2 74 0b 83 7c 81 04 00 74 1b 84 d2 75 07 83 7c 81 04 00 75 10 40 83 f8 23 72 de } //5
		$a_01_1 = {49 44 45 4e 20 2d 20 46 6f 72 6d 47 72 61 62 62 65 72 20 2d } //2 IDEN - FormGrabber -
		$a_01_2 = {52 54 5f 52 43 44 41 54 41 00 00 00 31 33 33 37 00 } //1
		$a_01_3 = {61 57 56 34 63 47 78 76 63 6d 55 75 5a 58 68 6c } //1 aWV4cGxvcmUuZXhl
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=7
 
}