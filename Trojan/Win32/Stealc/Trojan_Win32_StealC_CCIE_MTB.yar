
rule Trojan_Win32_StealC_CCIE_MTB{
	meta:
		description = "Trojan:Win32/StealC.CCIE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c3 d3 e8 89 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 8b 45 90 01 01 81 c2 90 01 04 33 45 90 01 01 8b 4d 90 01 01 33 c8 89 55 90 01 01 2b f9 89 4d 90 01 01 8b 4d 90 01 01 89 7d 90 01 01 4e 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}