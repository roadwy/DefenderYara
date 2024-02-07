
rule Trojan_BAT_Rozena_SPC_MTB{
	meta:
		description = "Trojan:BAT/Rozena.SPC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {07 17 58 0b 08 06 8e 69 17 58 33 11 06 08 8f 90 01 03 01 28 90 01 03 0a 28 90 01 03 0a 08 06 8e 69 2e 1b 06 08 8f 90 01 03 01 28 90 01 03 0a 72 90 01 03 70 28 90 01 03 0a 28 90 01 03 0a 08 17 58 0c 08 06 8e 69 32 b8 90 00 } //01 00 
		$a_01_1 = {61 6e 74 69 2d 76 69 72 75 73 2e 64 6c 6c } //00 00  anti-virus.dll
	condition:
		any of ($a_*)
 
}