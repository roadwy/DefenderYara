
rule Trojan_Win32_Qukart_GMC_MTB{
	meta:
		description = "Trojan:Win32/Qukart.GMC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {65 68 51 45 79 45 41 63 39 6f } //01 00  ehQEyEAc9o
		$a_01_1 = {47 74 61 52 46 5a 6a 42 30 } //01 00  GtaRFZjB0
		$a_01_2 = {65 52 4b 76 65 46 4e 5a 66 } //01 00  eRKveFNZf
		$a_01_3 = {67 44 69 59 48 49 52 64 35 } //01 00  gDiYHIRd5
		$a_01_4 = {4c 49 6e 46 77 74 7a 6a } //00 00  LInFwtzj
	condition:
		any of ($a_*)
 
}