
rule Trojan_Win32_LummaC_EATE_MTB{
	meta:
		description = "Trojan:Win32/LummaC.EATE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 d6 c1 ee 1e 31 d6 69 d6 65 89 07 6c 01 ca 83 c2 fe 89 54 88 fc 81 f9 71 02 00 00 74 18 89 d6 c1 ee 1e 31 d6 69 d6 65 89 07 6c 01 ca 4a 89 14 88 83 c1 02 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}