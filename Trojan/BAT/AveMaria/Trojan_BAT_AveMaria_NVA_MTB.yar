
rule Trojan_BAT_AveMaria_NVA_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 1f 20 28 13 00 00 06 73 ?? ?? ?? 0a 0b 07 03 1f 24 28 ?? ?? ?? 06 03 8e 69 6f ?? ?? ?? 0a 00 07 6f ?? ?? ?? 0a } //5
		$a_01_1 = {50 4f 4d 4e 42 38 37 36 2e 50 72 6f 70 65 72 74 69 65 73 } //1 POMNB876.Properties
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}