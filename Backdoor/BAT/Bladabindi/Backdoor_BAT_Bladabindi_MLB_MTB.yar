
rule Backdoor_BAT_Bladabindi_MLB_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.MLB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {0a 06 14 72 90 01 04 18 8d 90 01 04 25 17 17 8d 90 01 04 25 16 17 8d 90 01 04 25 16 7e 90 01 04 a2 a2 a2 14 14 14 28 90 01 04 26 90 09 0c 00 90 01 01 02 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}