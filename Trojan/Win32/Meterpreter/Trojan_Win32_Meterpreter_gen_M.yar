
rule Trojan_Win32_Meterpreter_gen_M{
	meta:
		description = "Trojan:Win32/Meterpreter.gen!M,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6a 01 8d 85 b2 00 00 00 50 68 31 8b 6f 87 ff } //1
		$a_02_1 = {6e 65 74 20 75 73 65 72 20 90 1d 20 00 20 [0-20] 20 2f 61 64 64 20 26 26 20 6e 65 74 20 6c 6f 63 61 6c 67 72 6f 75 70 20 61 64 6d 69 6e 69 73 74 72 61 74 6f 72 73 20 90 1d 20 00 20 2f 61 64 64 } //1
		$a_01_2 = {66 8b 0c 4b 8b 58 1c 01 d3 8b 04 8b 01 d0 89 44 24 24 5b 5b 61 59 5a 51 ff e0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_02_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}