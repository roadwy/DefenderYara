
rule Trojan_Win64_Meterpreter_K{
	meta:
		description = "Trojan:Win64/Meterpreter.K,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {2f 6c 65 73 6e 75 61 67 65 73 2f 68 65 72 73 68 65 6c 6c 2f 6d 65 74 65 72 70 72 65 74 65 72 2e 4d 65 74 65 72 70 72 65 74 65 72 } //1 /lesnuages/hershell/meterpreter.Meterpreter
		$a_01_1 = {2f 6c 65 73 6e 75 61 67 65 73 2f 68 65 72 73 68 65 6c 6c 2f 6d 65 74 65 72 70 72 65 74 65 72 2e 47 65 6e 65 72 61 74 65 55 52 49 43 68 65 63 6b 73 75 6d } //1 /lesnuages/hershell/meterpreter.GenerateURIChecksum
		$a_01_2 = {41 6c 69 76 65 4b 68 61 72 6f 73 68 74 68 69 4d 61 6e 69 63 68 61 65 61 6e 4d 65 73 73 61 67 65 } //1 AliveKharoshthiManichaeanMessage
		$a_01_3 = {75 6e 69 78 70 61 63 6b 65 74 75 6e 6b 6e 6f 77 6e 20 70 63 75 73 65 72 2d 61 67 65 6e 74 77 73 32 5f 33 32 2e 64 6c 6c } //1 unixpacketunknown pcuser-agentws2_32.dll
		$a_01_4 = {6d 63 61 63 68 65 6d 65 74 65 72 70 72 65 74 65 72 6d 65 74 68 6f 64 61 72 67 73 } //1 mcachemeterpretermethodargs
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}