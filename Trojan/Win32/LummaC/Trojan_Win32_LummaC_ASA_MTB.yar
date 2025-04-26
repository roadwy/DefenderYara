
rule Trojan_Win32_LummaC_ASA_MTB{
	meta:
		description = "Trojan:Win32/LummaC.ASA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 d6 81 e6 ef 00 00 00 89 cb 83 e3 10 09 f3 0f b6 74 0f e2 83 f3 10 21 d3 31 d3 f7 d3 21 f3 31 d3 b0 69 28 d8 88 44 0f e2 41 4a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}