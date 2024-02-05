
rule Trojan_BAT_Bobik_PSMO_MTB{
	meta:
		description = "Trojan:BAT/Bobik.PSMO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {00 16 13 04 07 8e 69 28 46 00 00 0a 13 05 02 7b 05 00 00 04 11 05 6f 47 00 00 0a 26 2b 1c } //00 00 
	condition:
		any of ($a_*)
 
}