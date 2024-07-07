
rule Trojan_Win32_TinyNuke_AD_MTB{
	meta:
		description = "Trojan:Win32/TinyNuke.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_01_0 = {4d 61 69 6e 53 74 75 62 2e 64 6c 6c } //5 MainStub.dll
		$a_01_1 = {51 62 6a 44 50 53 58 64 5a 6b 50 41 76 53 6d 43 4e 6b } //1 QbjDPSXdZkPAvSmCNk
		$a_01_2 = {56 53 67 50 73 52 73 6a 6d 4d 47 75 48 62 58 76 42 48 } //1 VSgPsRsjmMGuHbXvBH
		$a_01_3 = {61 63 77 74 4b 71 4d 6e 5a 53 54 7a 65 47 6c 4e 61 56 } //1 acwtKqMnZSTzeGlNaV
		$a_01_4 = {43 75 72 72 65 6e 74 53 74 61 6b 65 } //1 CurrentStake
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=9
 
}