
rule Trojan_Win32_Emotet_BM{
	meta:
		description = "Trojan:Win32/Emotet.BM,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {5a 00 62 00 73 00 75 00 69 00 74 00 65 00 73 00 75 00 66 00 66 00 65 00 72 00 69 00 6e 00 67 00 4f 00 74 00 65 00 73 00 74 00 73 00 } //1 ZbsuitesufferingOtests
		$a_01_1 = {56 00 63 00 72 00 61 00 73 00 68 00 63 00 6c 00 61 00 73 00 73 00 75 00 69 00 6e 00 66 00 6f 00 72 00 6d 00 61 00 74 00 69 00 6f 00 6e 00 35 00 35 00 69 00 74 00 } //1 Vcrashclassuinformation55it
		$a_01_2 = {74 00 68 00 65 00 54 00 65 00 72 00 6d 00 73 00 72 00 4d 00 61 00 69 00 6e 00 77 00 65 00 62 00 43 00 68 00 72 00 6f 00 6d 00 65 00 } //1 theTermsrMainwebChrome
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}