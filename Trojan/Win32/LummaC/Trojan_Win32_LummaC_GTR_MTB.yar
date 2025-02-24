
rule Trojan_Win32_LummaC_GTR_MTB{
	meta:
		description = "Trojan:Win32/LummaC.GTR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {40 00 00 e0 2e 72 73 72 63 00 00 00 b0 02 00 00 00 70 05 00 00 04 00 00 00 70 05 } //5
		$a_01_1 = {20 20 20 00 20 20 20 20 00 60 05 00 00 10 00 00 00 60 05 00 00 10 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}