
rule Trojan_Win32_LummaC_EWP_MTB{
	meta:
		description = "Trojan:Win32/LummaC.EWP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 fa 83 e2 03 32 04 13 88 46 01 46 47 49 75 f0 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}