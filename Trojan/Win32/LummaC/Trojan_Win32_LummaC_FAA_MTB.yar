
rule Trojan_Win32_LummaC_FAA_MTB{
	meta:
		description = "Trojan:Win32/LummaC.FAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 84 32 4b 13 01 00 8b 0d ?? ?? ?? ?? 88 04 31 81 3d ?? ?? ?? ?? 90 90 04 00 00 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}