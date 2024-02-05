
rule Backdoor_BAT_AsyncRAT_R_MTB{
	meta:
		description = "Backdoor:BAT/AsyncRAT.R!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {06 17 58 0a 06 20 00 01 00 00 5d 0a 08 11 06 06 94 58 0c 08 20 00 01 00 00 5d 0c 11 06 06 94 13 04 11 06 06 11 06 08 94 9e 2b 03 0b 2b 87 11 06 08 11 04 9e 2b 06 9e 38 90 01 01 ff ff ff 11 06 11 06 06 94 11 06 08 94 58 20 00 01 00 00 5d 94 0d 2b 06 9e 38 90 01 01 ff ff ff 11 07 07 03 07 91 09 61 d2 9c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}