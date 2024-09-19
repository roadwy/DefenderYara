
rule Trojan_Win32_LummaC_CCJL_MTB{
	meta:
		description = "Trojan:Win32/LummaC.CCJL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 0c 1a 8d 43 ?? 30 01 43 83 fb 14 72 f2 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}