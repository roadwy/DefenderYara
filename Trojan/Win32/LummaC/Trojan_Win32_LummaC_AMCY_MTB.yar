
rule Trojan_Win32_LummaC_AMCY_MTB{
	meta:
		description = "Trojan:Win32/LummaC.AMCY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 00 90 24 00 00 10 00 00 00 90 24 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}