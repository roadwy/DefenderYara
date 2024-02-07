
rule Backdoor_Win64_CobaltStrikeLoader_IP_dha{
	meta:
		description = "Backdoor:Win64/CobaltStrikeLoader.IP!dha,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {32 35 32 2e 37 32 2e 31 33 31 2e 32 32 38 } //01 00  252.72.131.228
		$a_00_1 = {32 34 30 2e 32 33 32 2e 32 30 30 2e 30 } //01 00  240.232.200.0
		$a_00_2 = {30 2e 30 2e 36 35 2e 38 31 } //01 00  0.0.65.81
		$a_00_3 = {36 35 2e 38 30 2e 38 32 2e 38 31 } //01 00  65.80.82.81
		$a_00_4 = {38 36 2e 37 32 2e 34 39 2e 32 31 30 } //01 00  86.72.49.210
		$a_00_5 = {31 30 31 2e 37 32 2e 31 33 39 2e 38 32 } //01 00  101.72.139.82
		$a_01_6 = {52 74 6c 49 70 76 34 53 74 72 69 6e 67 54 6f 41 64 64 72 65 73 73 41 } //00 00  RtlIpv4StringToAddressA
	condition:
		any of ($a_*)
 
}