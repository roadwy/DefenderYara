
rule Trojan_BAT_AveMaria_NEDC_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEDC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {2b 34 16 2b 34 2b 39 2b 3e 2b 09 2b 0a 2b 0b 16 2d f7 de 17 09 2b f4 08 2b f3 6f 90 01 01 00 00 0a 2b ee 09 2c 06 09 6f 90 01 01 00 00 0a dc 2b 1d 6f 90 01 01 00 00 0a 13 04 de 60 07 2b c9 90 00 } //02 00 
		$a_01_1 = {50 6f 77 65 72 65 64 20 62 79 20 53 6d 61 72 74 41 73 73 65 6d 62 6c 79 20 38 2e 31 2e 30 2e 34 38 39 32 } //00 00 
	condition:
		any of ($a_*)
 
}