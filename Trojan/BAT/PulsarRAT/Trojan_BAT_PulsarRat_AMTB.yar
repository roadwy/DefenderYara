
rule Trojan_BAT_PulsarRat_AMTB{
	meta:
		description = "Trojan:BAT/PulsarRat!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {43 00 3a 00 5c 00 54 00 45 00 4d 00 50 00 5c 00 70 00 73 00 31 00 70 00 72 00 6f 00 74 00 65 00 63 00 74 00 6f 00 72 00 5f 00 [0-30] 2e 00 6c 00 6f 00 67 00 } //1
		$a_80_1 = {52 55 4e 4e 45 52 5f 55 52 4c } //RUNNER_URL  1
		$a_80_2 = {70 73 31 70 5f } //ps1p_  1
	condition:
		((#a_02_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}