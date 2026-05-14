
rule Trojan_Win64_Keylogger_MK_MTB{
	meta:
		description = "Trojan:Win64/Keylogger.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 05 00 00 "
		
	strings :
		$a_01_0 = {48 8b 85 e8 14 00 00 8b 40 04 c1 e0 10 89 85 e4 14 00 00 48 8b 85 e8 14 00 00 8b 40 08 c1 e0 18 01 85 e4 14 } //25
		$a_01_1 = {4b 65 79 6c 6f 67 67 65 72 20 69 73 20 75 70 20 61 6e 64 20 72 75 6e 6e 69 6e 67 2e 2e 2e } //5 Keylogger is up and running...
		$a_01_2 = {48 6f 6f 6b 20 70 72 6f 63 65 64 75 72 65 20 68 61 73 20 62 65 65 6e 20 69 6e 73 74 61 6c 6c 65 64 20 73 75 63 63 65 73 73 66 75 6c 6c 79 } //5 Hook procedure has been installed successfully
		$a_01_3 = {5b 57 49 4e 20 4b 45 59 5d } //3 [WIN KEY]
		$a_01_4 = {5b 50 52 54 20 53 43 5d } //2 [PRT SC]
	condition:
		((#a_01_0  & 1)*25+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*3+(#a_01_4  & 1)*2) >=35
 
}