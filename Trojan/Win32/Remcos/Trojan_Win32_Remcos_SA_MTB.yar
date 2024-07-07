
rule Trojan_Win32_Remcos_SA_MTB{
	meta:
		description = "Trojan:Win32/Remcos.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b cb 8b c1 83 e0 90 01 01 8a 44 05 90 01 01 30 81 90 01 04 41 81 f9 90 01 02 00 00 72 90 01 01 68 90 01 04 68 90 01 04 68 90 01 04 b8 90 1b 02 ff d0 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}