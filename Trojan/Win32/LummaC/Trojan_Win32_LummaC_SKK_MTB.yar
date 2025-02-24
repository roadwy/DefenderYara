
rule Trojan_Win32_LummaC_SKK_MTB{
	meta:
		description = "Trojan:Win32/LummaC.SKK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 d8 24 fc 00 c8 32 02 34 42 04 b6 88 02 42 83 c3 02 fe c1 83 fb 08 75 e7 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}