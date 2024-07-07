
rule Worm_Win32_Seykr_A{
	meta:
		description = "Worm:Win32/Seykr.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {6a 00 6a 02 6a 00 6a 56 e8 90 01 04 6a 00 6a 02 6a 00 6a 11 e8 90 01 04 6a 00 6a 00 6a 00 6a 0d e8 90 01 04 6a 00 6a 02 6a 00 6a 0d e8 90 00 } //1
		$a_03_1 = {00 53 6b 79 70 65 90 02 10 46 61 63 65 62 6f 6f 6b 00 90 00 } //1
		$a_01_2 = {00 26 73 74 61 72 74 20 65 78 70 6c 6f 72 65 72 20 00 } //1 ☀瑳牡⁴硥汰牯牥 
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}