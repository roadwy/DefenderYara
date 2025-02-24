
rule Trojan_Win32_LummaC_FAD_MTB{
	meta:
		description = "Trojan:Win32/LummaC.FAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {87 d1 03 f3 33 d5 4f f7 d3 f7 12 46 f7 d3 33 dd f7 d6 49 2b df f7 de 33 c7 c1 c3 13 f7 d6 f7 d6 c1 cb 13 33 c7 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}