
rule Trojan_BAT_AveMaria_NEEZ_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEEZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 72 01 00 00 70 28 ?? 00 00 06 0a 28 ?? 00 00 0a 06 6f ?? 00 00 0a 28 ?? 00 00 0a 0b 02 07 28 ?? 00 00 06 0c dd 06 00 00 00 26 } //10
		$a_01_1 = {53 65 72 69 6c 6f 67 2e 53 69 6e 6b 73 2e 44 69 61 67 6e 6f 73 74 69 63 54 72 61 63 65 } //2 Serilog.Sinks.DiagnosticTrace
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*2) >=12
 
}