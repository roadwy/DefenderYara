
rule Backdoor_BAT_AsyncRAT_Y_MTB{
	meta:
		description = "Backdoor:BAT/AsyncRAT.Y!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {20 e8 03 00 00 28 90 01 01 00 00 06 20 90 01 03 13 2b 90 01 01 06 17 58 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}