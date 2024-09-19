
rule Trojan_Win32_LummaC_CZ_MTB{
	meta:
		description = "Trojan:Win32/LummaC.CZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 0c 98 8b 44 24 ?? 8a 04 01 8d 4c 24 ?? 30 82 } //1
		$a_03_1 = {46 89 74 24 ?? 81 fe ?? ?? ?? ?? 0f 8c } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}