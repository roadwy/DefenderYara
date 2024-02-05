
rule Backdoor_BAT_AsyncRAT_GKH_MTB{
	meta:
		description = "Backdoor:BAT/AsyncRAT.GKH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {73 79 00 00 0a 0a 06 28 90 01 03 0a 03 50 6f 90 01 03 0a 6f 90 01 03 0a 0b 73 7d 00 00 0a 0c 08 07 6f 90 01 03 0a 08 18 6f 90 01 03 0a 08 6f 90 01 03 0a 02 50 16 02 50 8e 69 6f 90 01 03 0a 2a 90 00 } //01 00 
		$a_01_1 = {54 72 69 70 6c 65 44 45 53 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}