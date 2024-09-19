
rule Trojan_Win32_LummaC_CCJQ_MTB{
	meta:
		description = "Trojan:Win32/LummaC.CCJQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {f6 17 58 50 89 c0 35 ?? ?? ?? ?? 90 90 80 07 64 80 2f 88 58 50 89 c0 35 ?? ?? ?? ?? 90 90 f6 2f 47 e2 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}