
rule Trojan_Win32_LummaC_ASN_MTB{
	meta:
		description = "Trojan:Win32/LummaC.ASN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {f6 17 90 89 d8 bb 99 00 00 00 90 31 c3 80 07 79 80 2f 35 90 89 d8 bb 99 00 00 00 90 31 c3 f6 2f 47 e2 } //4
		$a_01_1 = {8b 0a 8b 3e f6 17 53 5b 90 89 c3 83 f3 39 80 07 47 80 2f 25 53 5b 90 89 c3 83 f3 39 f6 2f 47 e2 } //4
		$a_01_2 = {20 ca 30 c8 08 c2 } //1
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*4+(#a_01_2  & 1)*1) >=5
 
}