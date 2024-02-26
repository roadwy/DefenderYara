
rule Trojan_BAT_Heracles_PTGA_MTB{
	meta:
		description = "Trojan:BAT/Heracles.PTGA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {8d f0 00 00 01 13 05 11 09 20 26 a0 ac 95 5a 20 a3 cd 1e 82 61 2b bb 09 11 04 11 04 8e 69 28 90 01 01 00 00 06 11 09 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}