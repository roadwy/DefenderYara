
rule Trojan_Win32_Neurevt_B{
	meta:
		description = "Trojan:Win32/Neurevt.B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {e6 9c 18 ee c7 45 90 01 01 c8 8a 25 1d c7 45 90 01 01 00 02 ab 7f c7 45 90 01 01 10 00 05 ff 90 00 } //1
		$a_03_1 = {11 8a f8 82 c7 45 90 01 01 9b 1c 37 d2 c7 45 90 01 01 aa d8 9b 4d c7 45 90 01 01 64 b9 cc c1 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}