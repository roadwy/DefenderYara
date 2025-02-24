
rule Trojan_Win32_LummaC_FAB_MTB{
	meta:
		description = "Trojan:Win32/LummaC.FAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 84 32 4b 13 01 00 88 04 31 8b 0d ?? ?? ?? ?? 81 f9 ?? ?? ?? ?? 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}