
rule Trojan_Win32_LummaC_IGB_MTB{
	meta:
		description = "Trojan:Win32/LummaC.IGB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 fa 89 c3 c1 eb 12 89 c7 c1 ef 11 81 e7 e0 00 00 00 81 f3 f0 00 00 00 01 fb 8b 7c 24 ?? 88 1f 89 c3 c1 eb 0c 80 e3 3f 80 cb 80 88 5f 01 c1 e8 06 24 3f 0c 80 88 47 02 b0 3f } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}