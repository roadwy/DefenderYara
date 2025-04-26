
rule Trojan_BAT_AveMaria_NT_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {72 75 00 00 70 0a 06 28 ?? 00 00 0a 25 26 0b 28 ?? 00 00 0a 07 16 07 8e 69 6f ?? 00 00 0a 0a 28 ?? 00 00 0a 25 26 06 6f ?? 00 00 0a } //5
		$a_01_1 = {50 4f 4d 4e 42 38 37 36 2e 50 72 6f 70 65 72 74 69 65 73 } //1 POMNB876.Properties
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}