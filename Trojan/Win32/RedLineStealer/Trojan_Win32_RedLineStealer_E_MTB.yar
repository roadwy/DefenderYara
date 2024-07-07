
rule Trojan_Win32_RedLineStealer_E_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 08 83 2c 24 90 01 02 01 04 24 8b 04 24 31 01 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}