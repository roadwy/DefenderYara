
rule Trojan_Win32_Conhook_I{
	meta:
		description = "Trojan:Win32/Conhook.I,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 09 00 00 00 68 0e f2 f8 4f } //1
		$a_01_1 = {68 0d 00 00 00 68 c2 2b 12 57 } //1
		$a_01_2 = {68 01 00 00 00 68 a6 7e c6 41 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}