
rule VirTool_Win32_Meterpreter_gen_A{
	meta:
		description = "VirTool:Win32/Meterpreter.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_80_0 = {4d 65 74 65 72 70 72 65 74 65 72 50 72 6f 63 65 73 73 28 4d 65 74 65 72 70 72 65 74 65 72 43 68 61 6e 6e 65 6c 29 } //MeterpreterProcess(MeterpreterChannel)  1
		$a_80_1 = {73 75 70 65 72 28 4d 65 74 65 72 70 72 65 74 65 72 53 6f 63 6b 65 74 55 44 50 43 6c 69 65 6e 74 } //super(MeterpreterSocketUDPClient  1
		$a_80_2 = {50 79 74 68 6f 6e 4d 65 74 65 72 70 72 65 74 65 72 28 74 72 61 6e 73 70 6f 72 74 29 } //PythonMeterpreter(transport)  1
		$a_80_3 = {61 64 64 5f 63 68 61 6e 6e 65 6c 28 4d 65 74 65 72 70 72 65 74 65 72 53 6f 63 6b 65 74 54 43 50 43 6c 69 65 6e 74 } //add_channel(MeterpreterSocketTCPClient  1
		$a_80_4 = {78 6f 72 5f 62 79 74 65 73 28 78 6f 72 5f 6b 65 79 } //xor_bytes(xor_key  1
		$a_80_5 = {72 75 6e 63 6f 64 65 28 63 6f 6d 70 69 6c 65 } //runcode(compile  1
		$a_80_6 = {5f 74 72 79 5f 74 6f 5f 66 6f 72 6b } //_try_to_fork  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=7
 
}
rule VirTool_Win32_Meterpreter_gen_A_2{
	meta:
		description = "VirTool:Win32/Meterpreter.gen!A!!Meterpreter.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_80_0 = {4d 65 74 65 72 70 72 65 74 65 72 50 72 6f 63 65 73 73 28 4d 65 74 65 72 70 72 65 74 65 72 43 68 61 6e 6e 65 6c 29 } //MeterpreterProcess(MeterpreterChannel)  1
		$a_80_1 = {73 75 70 65 72 28 4d 65 74 65 72 70 72 65 74 65 72 53 6f 63 6b 65 74 55 44 50 43 6c 69 65 6e 74 } //super(MeterpreterSocketUDPClient  1
		$a_80_2 = {50 79 74 68 6f 6e 4d 65 74 65 72 70 72 65 74 65 72 28 74 72 61 6e 73 70 6f 72 74 29 } //PythonMeterpreter(transport)  1
		$a_80_3 = {61 64 64 5f 63 68 61 6e 6e 65 6c 28 4d 65 74 65 72 70 72 65 74 65 72 53 6f 63 6b 65 74 54 43 50 43 6c 69 65 6e 74 } //add_channel(MeterpreterSocketTCPClient  1
		$a_80_4 = {78 6f 72 5f 62 79 74 65 73 28 78 6f 72 5f 6b 65 79 } //xor_bytes(xor_key  1
		$a_80_5 = {72 75 6e 63 6f 64 65 28 63 6f 6d 70 69 6c 65 } //runcode(compile  1
		$a_80_6 = {5f 74 72 79 5f 74 6f 5f 66 6f 72 6b } //_try_to_fork  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=7
 
}