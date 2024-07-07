
rule Trojan_Win32_TitanStealer_RDA_MTB{
	meta:
		description = "Trojan:Win32/TitanStealer.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b f0 8b c6 c1 e8 05 c7 05 90 01 08 89 45 0c 8b 45 ec 01 45 0c 8b c6 c1 e0 04 03 45 e8 03 de 33 c3 33 45 0c 50 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}