
rule Trojan_Win32_Qukart_GMC_MTB{
	meta:
		description = "Trojan:Win32/Qukart.GMC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {65 68 51 45 79 45 41 63 39 6f } //1 ehQEyEAc9o
		$a_01_1 = {47 74 61 52 46 5a 6a 42 30 } //1 GtaRFZjB0
		$a_01_2 = {65 52 4b 76 65 46 4e 5a 66 } //1 eRKveFNZf
		$a_01_3 = {67 44 69 59 48 49 52 64 35 } //1 gDiYHIRd5
		$a_01_4 = {4c 49 6e 46 77 74 7a 6a } //1 LInFwtzj
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}