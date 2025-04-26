
rule Trojan_Win32_LummaC_PMK_MTB{
	meta:
		description = "Trojan:Win32/LummaC.PMK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c0 0f 1f 44 00 00 8b c8 83 e1 03 8a 4c 0d ?? 30 0c 02 40 3b c6 72 ef 47 eb } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}