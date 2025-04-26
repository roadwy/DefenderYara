
rule Trojan_Win32_LummaC_MBV_MTB{
	meta:
		description = "Trojan:Win32/LummaC.MBV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 ce 83 e6 74 89 d3 81 f3 c5 00 00 00 29 f3 fe c3 32 18 80 c3 ?? 88 18 40 4a 83 c1 fe 83 fa ed 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}