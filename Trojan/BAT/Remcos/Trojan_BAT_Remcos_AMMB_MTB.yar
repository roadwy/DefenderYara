
rule Trojan_BAT_Remcos_AMMB_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AMMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 05 0e 07 0e 04 8e 69 6f ?? 00 00 0a 0a 06 0b 2b 00 07 2a } //2
		$a_03_1 = {0a 00 02 03 02 03 02 02 03 05 28 ?? 00 00 06 0a 2b 00 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}