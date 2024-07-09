
rule Trojan_BAT_Bladabindi_MBJC_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.MBJC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 72 ff 01 00 70 16 14 28 ?? 00 00 0a 26 00 2a } //1
		$a_01_1 = {39 62 2d 32 37 30 61 65 33 32 37 61 31 32 } //1 9b-270ae327a12
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}