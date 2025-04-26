
rule Trojan_BAT_Remcos_AMBE_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AMBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 02 04 03 8e 69 6f ?? 00 00 0a 0a 06 0b 2b 00 07 2a } //1
		$a_03_1 = {0a 00 02 03 05 28 ?? 00 00 06 0b 2b 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}