
rule Backdoor_BAT_Bladabindi_KAY_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.KAY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {84 95 d7 6e 20 ff 00 00 00 6a 5f b7 95 61 86 9c 00 } //00 00 
	condition:
		any of ($a_*)
 
}