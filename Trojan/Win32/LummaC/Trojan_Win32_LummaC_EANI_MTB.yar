
rule Trojan_Win32_LummaC_EANI_MTB{
	meta:
		description = "Trojan:Win32/LummaC.EANI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 ec 10 0f b7 45 da 83 c0 01 66 89 45 da 8b 45 cc 0f b7 40 06 66 39 45 da } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}