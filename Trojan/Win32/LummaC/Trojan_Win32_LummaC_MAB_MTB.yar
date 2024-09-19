
rule Trojan_Win32_LummaC_MAB_MTB{
	meta:
		description = "Trojan:Win32/LummaC.MAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 7c 24 30 8b 0c b3 0f b6 04 37 6a 03 30 81 ?? ?? ?? ?? b9 } //1
		$a_03_1 = {45 89 6c 24 14 81 fd ?? ?? ?? ?? 7d } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}