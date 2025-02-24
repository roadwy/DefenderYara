
rule Trojan_Win32_LummaC_AVCA_MTB{
	meta:
		description = "Trojan:Win32/LummaC.AVCA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c6 83 e6 ?? 89 d3 81 f3 ?? 00 00 00 01 f3 32 1c 14 fe cb 88 1c 14 42 83 c0 02 83 fa 05 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}