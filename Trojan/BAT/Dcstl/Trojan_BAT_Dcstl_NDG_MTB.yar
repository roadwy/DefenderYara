
rule Trojan_BAT_Dcstl_NDG_MTB{
	meta:
		description = "Trojan:BAT/Dcstl.NDG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {72 b8 19 00 70 28 90 01 02 00 0a 0d 09 28 90 01 02 00 0a 13 05 11 05 2c 13 00 07 72 90 01 02 00 70 28 90 01 02 00 0a 28 90 01 02 00 0a 90 00 } //01 00 
		$a_01_1 = {43 6f 6d 70 69 6c 65 72 4d 6f 64 75 6c 65 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}