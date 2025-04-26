
rule Trojan_Win32_LummaC_EA_MTB{
	meta:
		description = "Trojan:Win32/LummaC.EA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 8d 84 00 00 00 8b d3 c1 ea 08 88 14 08 ff 85 84 00 00 00 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_Win32_LummaC_EA_MTB_2{
	meta:
		description = "Trojan:Win32/LummaC.EA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 88 b8 00 00 00 8b 85 84 00 00 00 8b d3 c1 ea 08 88 14 01 ff 85 84 00 00 00 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}