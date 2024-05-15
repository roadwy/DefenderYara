
rule Trojan_BAT_Zusy_GP_MTB{
	meta:
		description = "Trojan:BAT/Zusy.GP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8d 1d 00 00 01 25 d0 ae 00 00 04 28 20 00 00 0a 6f 90 01 01 00 00 0a 06 07 6f 90 01 01 00 00 0a 17 73 81 00 00 0a 25 02 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}