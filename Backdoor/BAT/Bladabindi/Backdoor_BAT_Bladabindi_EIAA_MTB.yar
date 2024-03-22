
rule Backdoor_BAT_Bladabindi_EIAA_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.EIAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {7e 01 00 00 04 20 e8 03 00 00 73 90 01 01 00 00 0a 0d 08 09 08 6f 90 01 01 00 00 0a 1e 5b 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 00 08 09 08 6f 90 01 01 00 00 0a 1e 5b 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 00 08 17 6f 90 01 01 00 00 0a 00 07 08 6f 90 01 01 00 00 0a 17 73 90 01 01 00 00 0a 13 04 00 11 04 02 16 02 8e 69 6f 90 01 01 00 00 0a 00 11 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}