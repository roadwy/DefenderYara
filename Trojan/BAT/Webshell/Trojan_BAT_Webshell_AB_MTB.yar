
rule Trojan_BAT_Webshell_AB_MTB{
	meta:
		description = "Trojan:BAT/Webshell.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {73 1c 00 00 0a 28 14 00 00 0a 07 6f 16 00 00 0a 28 14 00 00 0a 07 6f 16 00 00 0a 6f 2d 00 00 0a 11 06 16 11 06 8e 69 6f 1e 00 00 0a 28 2e 00 00 0a 6f 2c 00 00 0a 02 6f 0a 00 00 0a 6f 2a 00 00 0a 08 1f 10 6f 2f 00 00 0a 6f 2c 00 00 0a de 03 26 } //05 00 
		$a_03_1 = {28 10 00 00 0a 28 10 00 00 0a 28 10 00 00 0a 72 90 01 04 28 11 00 00 0a 6f 12 00 00 0a 28 11 00 00 0a 6f 12 00 00 0a 28 11 00 00 0a 6f 12 00 00 0a 0a 72 90 01 04 0b 73 13 00 00 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}