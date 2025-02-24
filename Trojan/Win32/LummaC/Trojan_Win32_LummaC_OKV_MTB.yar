
rule Trojan_Win32_LummaC_OKV_MTB{
	meta:
		description = "Trojan:Win32/LummaC.OKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 ca 80 c2 c9 32 14 08 80 c2 6e 88 14 08 41 83 f9 20 75 ?? 50 e8 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}