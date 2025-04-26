
rule Trojan_Win32_LummaC_CCIP_MTB{
	meta:
		description = "Trojan:Win32/LummaC.CCIP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 61 37 35 c7 44 24 ?? 65 39 65 35 c7 44 24 ?? 31 37 66 63 c7 44 24 ?? 65 32 64 33 c7 44 ?? 24 61 62 66 33 c7 44 24 ?? 37 34 64 36 c7 44 24 ?? 66 63 32 32 c7 44 24 ?? 64 30 65 33 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}