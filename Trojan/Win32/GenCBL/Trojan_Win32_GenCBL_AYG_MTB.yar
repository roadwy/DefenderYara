
rule Trojan_Win32_GenCBL_AYG_MTB{
	meta:
		description = "Trojan:Win32/GenCBL.AYG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {49 6e 74 65 6c 20 58 65 6f 6e 20 53 63 61 6c 61 62 6c 65 20 53 69 6c 76 65 72 20 33 72 64 20 47 65 6e 20 34 33 31 34 } //01 00  Intel Xeon Scalable Silver 3rd Gen 4314
		$a_81_1 = {4d 53 49 20 47 46 36 35 50 } //01 00  MSI GF65P
		$a_81_2 = {32 31 30 39 32 33 31 31 33 38 34 36 5a } //01 00  210923113846Z
		$a_81_3 = {33 31 30 39 32 34 31 31 33 38 34 36 5a 30 32 31 30 30 } //00 00  310924113846Z02100
	condition:
		any of ($a_*)
 
}