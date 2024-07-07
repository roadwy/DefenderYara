
rule Trojan_Win32_Vundo_AX{
	meta:
		description = "Trojan:Win32/Vundo.AX,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {b9 c6 15 c8 75 } //1
		$a_01_1 = {81 f1 28 76 58 2b } //1
		$a_01_2 = {b9 15 07 91 45 } //1
		$a_01_3 = {81 f1 4f 68 4f ec } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}