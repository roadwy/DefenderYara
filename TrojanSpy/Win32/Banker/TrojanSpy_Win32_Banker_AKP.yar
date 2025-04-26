
rule TrojanSpy_Win32_Banker_AKP{
	meta:
		description = "TrojanSpy:Win32/Banker.AKP,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 6f 49 57 42 51 51 41 5c 4b 42 43 37 4a 49 47 5c } //3 \oIWBQQA\KBC7JIG\
		$a_01_1 = {4f 49 36 54 37 36 54 2d 4e 37 36 6b 54 5a 3a 34 } //4 OI6T76T-N76kTZ:4
		$a_01_2 = {79 52 52 37 6d 54 3a 34 54 37 47 54 2f 5a 54 74 51 } //4 yRR7mT:4T7GT/ZTtQ
		$a_01_3 = {77 49 4a 54 33 41 43 37 5c 6f 42 52 43 49 65 49 4a 54 5c 31 42 36 73 49 33 65 5c 4f 76 43 43 37 36 54 70 37 43 65 42 49 36 5c 56 36 54 37 43 36 37 54 34 77 37 54 54 42 36 6b 65 5c 79 76 54 49 4f 49 36 4a 42 6b 4d 43 51 } //5 wIJT3AC7\oBRCIeIJT\1B6sI3e\OvCC76Tp7CeBI6\V6T7C67T4w7TTB6ke\yvTIOI6JBkMCQ
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*4+(#a_01_2  & 1)*4+(#a_01_3  & 1)*5) >=16
 
}