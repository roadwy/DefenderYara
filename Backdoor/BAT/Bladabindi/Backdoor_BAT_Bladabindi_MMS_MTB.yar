
rule Backdoor_BAT_Bladabindi_MMS_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.MMS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {11 0a a2 25 1f 0b 11 0b a2 28 90 01 0e 13 0c 11 0c 72 90 01 09 13 0d 11 0d 72 90 01 09 13 0e 73 90 01 09 11 0e 6f 90 01 04 14 17 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}