
rule Trojan_Win32_LummaC_CCJN_MTB{
	meta:
		description = "Trojan:Win32/LummaC.CCJN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {29 cf 81 c1 ?? ?? ?? ?? 31 cf 21 d7 31 cf 89 7e } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}