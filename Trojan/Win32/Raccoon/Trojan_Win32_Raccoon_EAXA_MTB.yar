
rule Trojan_Win32_Raccoon_EAXA_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.EAXA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b f0 d3 e0 c1 ee 05 03 b4 24 d8 02 00 00 03 84 24 d0 02 00 00 89 74 24 10 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}