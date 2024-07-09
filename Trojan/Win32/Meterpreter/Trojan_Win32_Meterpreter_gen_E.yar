
rule Trojan_Win32_Meterpreter_gen_E{
	meta:
		description = "Trojan:Win32/Meterpreter.gen!E,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {5d 68 33 32 00 00 68 77 73 32 5f 54 68 4c 77 26 07 } //1
		$a_01_1 = {8b 72 28 0f b7 4a 26 31 ff ac 3c 61 7c 02 2c 20 c1 cf 0d 01 c7 e2 f2 } //1
		$a_01_2 = {8b 04 8b 01 d0 89 44 24 24 5b 5b 61 59 5a 51 ff e0 } //1
		$a_03_3 = {6a 10 56 57 68 99 a5 74 61 ff d5 85 c0 74 ?? ff 4e 08 75 } //1
		$a_03_4 = {68 58 a4 53 e5 ff d5 [0-0a] 6a 00 56 53 57 68 02 d9 c8 5f ff d5 } //1
		$a_01_5 = {89 e6 50 50 50 50 40 50 40 50 68 ea 0f df e0 ff d5 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}