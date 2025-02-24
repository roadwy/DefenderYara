
rule Trojan_Win32_LummaC_AMCT_MTB{
	meta:
		description = "Trojan:Win32/LummaC.AMCT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 20 20 00 10 05 00 00 10 00 00 00 10 05 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 20 00 00 60 2e 72 73 72 63 00 00 00 00 10 00 00 00 20 05 00 00 10 00 00 00 20 05 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}