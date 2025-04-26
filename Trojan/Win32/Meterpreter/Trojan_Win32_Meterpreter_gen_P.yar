
rule Trojan_Win32_Meterpreter_gen_P{
	meta:
		description = "Trojan:Win32/Meterpreter.gen!P,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {86 c6 c2 04 18 33 32 2e 64 87 57 36 57 32 } //1
		$a_01_1 = {bb a8 a2 4d bc 87 1c 24 52 } //2
		$a_01_2 = {68 6f 78 58 20 68 61 67 65 42 68 4d 65 73 73 } //2 hoxX hageBhMess
		$a_01_3 = {68 8e 4e 0e ec 52 e8 } //1
		$a_01_4 = {88 4c 24 10 89 e1 31 d2 52 53 51 52 ff d0 31 c0 50 ff 55 08 } //1
		$a_01_5 = {8b 6c 24 24 8b 45 3c 8b 54 28 78 01 ea 8b 4a 18 8b 5a 20 01 eb e3 34 49 8b 34 8b 01 ee 31 ff 31 c0 fc ac } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}