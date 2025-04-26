
rule Trojan_Win32_Injuke_ASC_MTB{
	meta:
		description = "Trojan:Win32/Injuke.ASC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {2a 01 00 00 00 c6 5f 33 00 63 be [0-04] 0a 00 73 5b 0d ca d2 82 2f } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}