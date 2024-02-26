
rule Trojan_BAT_Badur_GNF_MTB{
	meta:
		description = "Trojan:BAT/Badur.GNF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 00 69 00 73 00 63 00 6f 00 72 00 64 00 2e 00 67 00 67 00 2f 00 46 00 68 00 41 00 58 00 55 00 4b 00 77 00 4e 00 6e 00 78 00 } //01 00  discord.gg/FhAXUKwNnx
		$a_80_1 = {69 6e 69 63 69 61 64 6f 72 20 6e 6f 20 70 75 64 6f 20 6c 65 65 72 20 6c 61 20 76 65 72 73 69 } //iniciador no pudo leer la versi  01 00 
		$a_80_2 = {73 34 2e 73 6f 6e 64 65 76 73 } //s4.sondevs  00 00 
	condition:
		any of ($a_*)
 
}