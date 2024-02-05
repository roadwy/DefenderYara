
rule Trojan_BAT_Nvisec_A{
	meta:
		description = "Trojan:BAT/Nvisec.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_80_0 = {2d 2d 20 4b 65 79 6c 6f 67 65 72 20 41 63 74 69 76 61 64 6f 20 } //-- Keyloger Activado   01 00 
		$a_80_1 = {52 65 73 75 6c 74 61 64 6f 20 43 6f 6d 61 6e 64 6f } //Resultado Comando  01 00 
		$a_80_2 = {6b 65 79 2e 53 63 72 65 65 6e } //key.Screen  01 00 
		$a_80_3 = {6b 65 79 2e 50 72 6f 63 65 73 73 } //key.Process  00 00 
	condition:
		any of ($a_*)
 
}