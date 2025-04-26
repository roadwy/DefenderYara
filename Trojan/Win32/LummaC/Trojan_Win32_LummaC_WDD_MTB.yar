
rule Trojan_Win32_LummaC_WDD_MTB{
	meta:
		description = "Trojan:Win32/LummaC.WDD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 c8 04 28 32 04 0a 04 38 88 04 0a 41 83 f9 07 75 ee } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}