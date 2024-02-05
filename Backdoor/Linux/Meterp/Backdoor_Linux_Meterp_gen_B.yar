
rule Backdoor_Linux_Meterp_gen_B{
	meta:
		description = "Backdoor:Linux/Meterp.gen!B!!Meterp.gen!B,SIGNATURE_TYPE_ARHSTR_EXT,02 00 02 00 05 00 00 02 00 "
		
	strings :
		$a_00_0 = {2f 6d 65 74 74 6c 65 2f 6d 65 74 74 6c 65 2f 73 72 63 2f 6d 61 69 6e 2e 63 } //01 00 
		$a_00_1 = {70 72 6f 63 65 73 73 5f 6b 69 6c 6c 5f 62 79 5f 70 69 64 } //01 00 
		$a_00_2 = {2d 2d 70 65 72 73 69 73 74 20 5b 6e 6f 6e 65 7c 69 6e 73 74 61 6c 6c 7c 75 6e 69 6e 73 74 61 6c 6c 5d 20 6d 61 6e 61 67 65 20 70 65 72 73 69 73 74 65 6e 63 65 } //01 00 
		$a_00_3 = {2d 2d 62 61 63 6b 67 72 6f 75 6e 64 20 5b 30 7c 31 5d 20 73 74 61 72 74 20 61 73 20 61 20 62 61 63 6b 67 72 6f 75 6e 64 20 73 65 72 76 69 63 65 } //02 00 
		$a_00_4 = {6d 65 74 74 6c 65 73 70 6c 6f 69 74 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_Linux_Meterp_gen_B_2{
	meta:
		description = "Backdoor:Linux/Meterp.gen!B!!Meterp.gen!B,SIGNATURE_TYPE_ARHSTR_EXT,02 00 02 00 07 00 00 01 00 "
		
	strings :
		$a_80_0 = {2f 6d 65 74 74 6c 65 2f 6d 65 74 74 6c 65 2f 73 72 63 2f 6d 65 74 74 6c 65 2e 63 } ///mettle/mettle/src/mettle.c  01 00 
		$a_80_1 = {2f 6d 65 74 74 6c 65 2f 6d 65 74 74 6c 65 2f 73 72 63 2f 63 32 5f 68 74 74 70 2e 63 } ///mettle/mettle/src/c2_http.c  01 00 
		$a_80_2 = {2f 6d 65 74 74 6c 65 2f 6d 65 74 74 6c 65 2f 73 72 63 2f 62 75 66 66 65 72 65 76 2e 63 } ///mettle/mettle/src/bufferev.c  01 00 
		$a_80_3 = {2f 6d 65 74 74 6c 65 2f 6d 65 74 74 6c 65 2f 73 72 63 2f 63 68 61 6e 6e 65 6c 2e 63 } ///mettle/mettle/src/channel.c  01 00 
		$a_80_4 = {2f 6d 65 74 74 6c 65 2f 6d 65 74 74 6c 65 2f 73 72 63 2f 63 6f 72 65 61 70 69 2e 63 } ///mettle/mettle/src/coreapi.c  01 00 
		$a_80_5 = {2f 6d 65 74 74 6c 65 2f 6d 65 74 74 6c 65 2f 73 72 63 2f 70 72 6f 63 65 73 73 2e 63 } ///mettle/mettle/src/process.c  01 00 
		$a_80_6 = {2f 6d 65 74 74 6c 65 2f 6d 65 74 74 6c 65 2f 73 72 63 2f 73 65 72 76 69 63 65 2e 63 } ///mettle/mettle/src/service.c  00 00 
	condition:
		any of ($a_*)
 
}