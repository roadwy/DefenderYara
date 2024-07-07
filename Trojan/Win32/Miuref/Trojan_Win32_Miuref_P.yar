
rule Trojan_Win32_Miuref_P{
	meta:
		description = "Trojan:Win32/Miuref.P,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 ff ff 15 90 01 03 10 68 90 01 03 10 33 c0 50 50 6a 28 50 ff 15 90 01 03 10 81 c6 20 03 00 00 81 c7 f4 01 00 00 3b fe 7c d8 90 09 05 00 be 90 01 02 01 00 90 00 } //1
		$a_03_1 = {71 02 10 34 90 01 01 2c 90 01 01 88 82 90 01 01 71 02 10 42 81 fa 00 2c 00 00 72 e7 90 09 03 00 8a 82 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}