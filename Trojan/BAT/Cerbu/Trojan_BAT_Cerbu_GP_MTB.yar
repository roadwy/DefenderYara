
rule Trojan_BAT_Cerbu_GP_MTB{
	meta:
		description = "Trojan:BAT/Cerbu.GP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_01_0 = {00 7e 13 00 00 0a 1a 2c 1f 16 25 2d 0c 2b 3f 16 20 7f 96 98 00 2b 3e 2b 43 12 02 2b 42 2b 47 1e 2d 4b 26 18 2b 4a 2b 4b 2b 4c 07 28 01 00 00 06 26 } //00 00 
	condition:
		any of ($a_*)
 
}