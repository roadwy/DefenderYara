
rule Backdoor_BAT_Cudsicam_A{
	meta:
		description = "Backdoor:BAT/Cudsicam.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 6d 64 53 75 69 63 69 64 00 53 75 69 63 69 64 } //01 00  浃卤極楣d畓捩摩
		$a_01_1 = {50 61 72 73 65 43 6f 6d 6d 61 6e 64 00 63 6f 6d 6d 61 6e 64 00 63 6f 6d 6d 61 6e 64 4e 61 6d 65 } //01 00  慐獲䍥浯慭摮挀浯慭摮挀浯慭摮慎敭
		$a_01_2 = {43 6d 64 49 6e 73 74 61 6c 6c 00 57 65 62 43 6c 69 65 6e 74 00 53 79 73 74 65 6d 2e 4e 65 74 } //01 00 
		$a_01_3 = {46 6c 61 67 45 78 73 69 73 74 73 00 70 72 6d 73 00 66 6c 61 67 } //00 00 
	condition:
		any of ($a_*)
 
}