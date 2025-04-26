
rule Trojan_Win32_LummaC_ASS_MTB{
	meta:
		description = "Trojan:Win32/LummaC.ASS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 23 00 83 63 ?? 00 e8 [0-04] 8b 44 24 ?? 83 c4 0c 8a 4c 2c ?? 30 0c 38 83 7b 04 00 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}