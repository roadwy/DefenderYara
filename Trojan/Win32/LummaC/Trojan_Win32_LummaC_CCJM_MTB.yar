
rule Trojan_Win32_LummaC_CCJM_MTB{
	meta:
		description = "Trojan:Win32/LummaC.CCJM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 ce 21 d6 01 f6 29 f2 01 ca 89 54 24 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}