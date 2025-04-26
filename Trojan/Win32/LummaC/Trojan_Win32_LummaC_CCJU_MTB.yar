
rule Trojan_Win32_LummaC_CCJU_MTB{
	meta:
		description = "Trojan:Win32/LummaC.CCJU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c1 80 c1 ?? 32 4c 04 02 80 c1 ?? 88 4c 04 02 40 83 f8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}