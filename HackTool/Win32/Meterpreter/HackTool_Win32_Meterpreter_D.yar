
rule HackTool_Win32_Meterpreter_D{
	meta:
		description = "HackTool:Win32/Meterpreter.D,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 65 00 63 00 68 00 6f 00 20 00 90 2a 06 00 20 00 3e 00 20 00 5c 00 5c 00 2e 00 5c 00 70 00 69 00 70 00 65 00 5c 00 90 2a 06 00 00 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}