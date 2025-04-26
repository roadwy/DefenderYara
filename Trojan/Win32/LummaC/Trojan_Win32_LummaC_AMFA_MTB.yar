
rule Trojan_Win32_LummaC_AMFA_MTB{
	meta:
		description = "Trojan:Win32/LummaC.AMFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 f9 00 c1 89 cf 0f b6 c9 0f b6 94 0c ?? ?? 00 00 88 94 2c ?? ?? 00 00 88 84 0c ?? ?? 00 00 02 84 2c ?? ?? 00 00 0f b6 c0 0f b6 84 04 ?? ?? 00 00 8b 8c 24 ?? ?? 00 00 30 04 19 43 39 9c 24 ?? ?? 00 00 74 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}