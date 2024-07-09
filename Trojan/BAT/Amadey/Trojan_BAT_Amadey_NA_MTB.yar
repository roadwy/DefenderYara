
rule Trojan_BAT_Amadey_NA_MTB{
	meta:
		description = "Trojan:BAT/Amadey.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 13 00 00 0a 28 ?? 00 00 0a 72 ?? 00 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a 25 28 ?? 00 00 06 28 ?? 00 00 0a 28 18 00 00 0a } //5
		$a_01_1 = {56 65 6e 6f 6d 6f 75 73 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 Venomous.Properties.Resources
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}