
rule Trojan_Win32_LummaC_CCJO_MTB{
	meta:
		description = "Trojan:Win32/LummaC.CCJO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 0c 24 8b 14 24 0f b6 54 14 ?? 81 c1 ?? ?? ?? ?? 31 d1 89 8c 24 ?? ?? ?? ?? 8b 8c 24 ?? ?? ?? ?? 80 c1 ?? 8b 14 24 88 4c 14 ?? ff 04 24 8b 0c 24 83 f9 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}