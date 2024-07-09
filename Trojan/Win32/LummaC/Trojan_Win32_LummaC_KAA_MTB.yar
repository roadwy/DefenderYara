
rule Trojan_Win32_LummaC_KAA_MTB{
	meta:
		description = "Trojan:Win32/LummaC.KAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 75 88 8a 84 05 ?? ?? ?? ?? 30 04 0b 43 3b 9d ?? ?? ?? ?? 89 5d ?? 8b 5d ?? 0f 8c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}