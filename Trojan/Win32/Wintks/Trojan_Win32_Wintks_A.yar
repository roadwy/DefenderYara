
rule Trojan_Win32_Wintks_A{
	meta:
		description = "Trojan:Win32/Wintks.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {76 0e 8a 0c 28 80 f1 08 88 0c 28 40 3b c3 72 f2 68 90 01 04 b9 90 01 04 e8 90 01 04 be 80 00 00 00 90 00 } //1
		$a_03_1 = {6a 0a 68 00 01 00 00 50 e8 90 01 02 00 00 8d 7c 24 10 83 c9 ff 33 c0 f2 ae f7 d1 49 8b f1 83 fe 38 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}