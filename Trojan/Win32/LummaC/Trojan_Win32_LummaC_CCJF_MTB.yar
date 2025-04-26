
rule Trojan_Win32_LummaC_CCJF_MTB{
	meta:
		description = "Trojan:Win32/LummaC.CCJF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {21 d0 01 f0 89 c2 31 ca f7 d0 21 c8 01 c0 29 d0 } //5
		$a_03_1 = {21 ca 01 c8 01 d2 29 d0 05 ?? ?? ?? ?? 89 44 24 ?? 8b 44 24 ?? 04 ?? 8b 0c 24 88 44 0c 08 ff 04 24 8b 04 24 83 f8 } //5
		$a_01_2 = {21 d0 01 c0 89 ca f7 d2 21 c2 f7 d0 21 c8 29 d0 89 44 24 } //5
		$a_03_3 = {21 c8 09 ca 29 c2 89 54 24 ?? 8b 44 24 ?? 04 1d 8b 0c 24 88 44 0c ?? ff 04 24 8b 04 24 83 f8 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*5+(#a_01_2  & 1)*5+(#a_03_3  & 1)*5) >=5
 
}