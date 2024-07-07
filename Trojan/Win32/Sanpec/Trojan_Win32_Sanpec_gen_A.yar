
rule Trojan_Win32_Sanpec_gen_A{
	meta:
		description = "Trojan:Win32/Sanpec.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 14 01 80 f2 90 01 01 88 10 40 90 01 01 75 f4 90 02 01 68 80 00 00 00 90 00 } //1
		$a_03_1 = {05 78 56 34 12 83 c4 90 01 02 c9 90 01 05 90 02 01 7e 90 01 1a 8a 54 15 90 01 01 32 14 90 01 02 3b 90 02 02 88 10 7c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}