
rule Backdoor_Linux_Meterp_gen_A{
	meta:
		description = "Backdoor:Linux/Meterp.gen!A!!Meterp.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {4d 65 74 65 72 70 72 65 74 65 72 50 72 6f 63 65 73 73 28 4d 65 74 65 72 70 72 65 74 65 72 43 68 61 6e 6e 65 6c 29 } //01 00  MeterpreterProcess(MeterpreterChannel)
		$a_81_1 = {73 75 70 65 72 28 4d 65 74 65 72 70 72 65 74 65 72 53 6f 63 6b 65 74 55 44 50 43 6c 69 65 6e 74 } //01 00  super(MeterpreterSocketUDPClient
		$a_81_2 = {50 79 74 68 6f 6e 4d 65 74 65 72 70 72 65 74 65 72 28 74 72 61 6e 73 70 6f 72 74 29 } //01 00  PythonMeterpreter(transport)
		$a_81_3 = {61 64 64 5f 63 68 61 6e 6e 65 6c 28 4d 65 74 65 72 70 72 65 74 65 72 53 6f 63 6b 65 74 54 43 50 43 6c 69 65 6e 74 } //01 00  add_channel(MeterpreterSocketTCPClient
		$a_81_4 = {78 6f 72 5f 62 79 74 65 73 28 78 6f 72 5f 6b 65 79 } //01 00  xor_bytes(xor_key
		$a_81_5 = {72 75 6e 63 6f 64 65 28 63 6f 6d 70 69 6c 65 } //01 00  runcode(compile
		$a_81_6 = {6d 65 74 2e 72 75 6e 28 29 } //00 00  met.run()
	condition:
		any of ($a_*)
 
}