
rule Trojan_Win32_LummaC_CCJK_MTB{
	meta:
		description = "Trojan:Win32/LummaC.CCJK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {d4 45 d0 4b c7 44 24 ?? ee 49 e4 4f c7 44 24 ?? e2 4d 9e 33 c7 44 24 ?? 96 31 9c 37 c7 44 24 ?? 9a 35 34 3b } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}