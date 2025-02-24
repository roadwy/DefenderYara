
rule Trojan_Win32_LummaC_CCIQ_MTB{
	meta:
		description = "Trojan:Win32/LummaC.CCIQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {32 31 66 61 c7 44 24 ?? 39 38 35 61 c7 44 24 ?? 33 65 62 31 c7 44 24 ?? 34 36 33 35 c7 44 24 ?? 64 35 33 37 c7 44 24 ?? 37 64 64 31 c7 44 24 ?? 36 62 64 37 c7 44 24 ?? 33 35 32 36 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}