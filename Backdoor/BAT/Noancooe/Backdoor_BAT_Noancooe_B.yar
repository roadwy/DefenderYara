
rule Backdoor_BAT_Noancooe_B{
	meta:
		description = "Backdoor:BAT/Noancooe.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {4e 61 6e 6f 43 6f 72 65 2e 43 6c 69 65 6e 74 50 6c 75 67 69 6e 00 } //01 00  慎潮潃敲䌮楬湥側畬楧n
		$a_01_1 = {43 6f 6e 6e 65 63 74 69 6f 6e 53 74 61 74 65 43 68 61 6e 67 65 64 00 } //01 00 
		$a_01_2 = {53 65 6e 64 54 6f 53 65 72 76 65 72 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_BAT_Noancooe_B_2{
	meta:
		description = "Backdoor:BAT/Noancooe.B,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 00 6c 00 69 00 65 00 6e 00 74 00 20 00 6c 00 6f 00 67 00 67 00 69 00 6e 00 67 00 20 00 68 00 61 00 73 00 20 00 69 00 6e 00 69 00 74 00 69 00 61 00 6c 00 69 00 7a 00 65 00 64 00 } //01 00  Client logging has initialized
		$a_01_1 = {43 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 69 00 6e 00 67 00 20 00 74 00 6f 00 20 00 7b 00 30 00 7d 00 3a 00 7b 00 31 00 7d 00 2e 00 2e 00 } //01 00  Connecting to {0}:{1}..
		$a_01_2 = {43 00 6c 00 6f 00 73 00 69 00 6e 00 67 00 20 00 7b 00 30 00 3a 00 4e 00 30 00 7d 00 20 00 70 00 69 00 70 00 65 00 73 00 2e 00 2e 00 } //01 00  Closing {0:N0} pipes..
		$a_01_3 = {52 00 43 00 5f 00 44 00 41 00 54 00 41 00 } //01 00  RC_DATA
		$a_01_4 = {4e 61 6e 6f 43 6f 72 65 20 43 6c 69 65 6e 74 2e 65 78 65 } //00 00  NanoCore Client.exe
		$a_00_5 = {7e 15 00 } //00 04 
	condition:
		any of ($a_*)
 
}