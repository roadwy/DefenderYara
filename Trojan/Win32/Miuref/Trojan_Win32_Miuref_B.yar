
rule Trojan_Win32_Miuref_B{
	meta:
		description = "Trojan:Win32/Miuref.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b d8 33 c0 89 90 03 01 01 73 7b 04 89 43 0c 89 43 08 89 43 10 8b 90 03 01 01 46 47 54 03 90 01 01 3c 90 00 } //1
		$a_03_1 = {80 e3 0f 6a 01 80 fb 03 77 90 01 01 6a 06 58 e8 90 01 04 8b f8 59 6a 2e 58 66 89 07 90 02 01 0f b6 c3 66 83 c0 30 66 89 47 02 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}