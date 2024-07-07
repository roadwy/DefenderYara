
rule Trojan_Win32_Glupteba_DSC_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.DSC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {bb 87 d5 7c 3a 81 45 90 01 01 8c eb 73 22 8b 45 90 01 01 8b 4d 90 01 01 8b d0 d3 e2 8b c8 c1 e9 05 03 8d 90 02 04 03 95 90 02 04 89 3d 90 01 04 33 d1 8b 8d 90 02 04 03 c8 33 d1 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}