
rule Trojan_Win64_Winnti_K_dha{
	meta:
		description = "Trojan:Win64/Winnti.K!dha,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {77 6f 72 6b 5f 65 6e 64 } //1 work_end
		$a_01_1 = {77 6f 72 6b 5f 73 74 61 72 74 } //1 work_start
		$a_01_2 = {47 65 74 41 73 79 6e 63 4b 65 79 53 74 61 74 65 } //1 GetAsyncKeyState
		$a_01_3 = {47 65 74 4b 65 79 53 74 61 74 65 } //1 GetKeyState
		$a_01_4 = {5b 50 61 67 65 44 6f 77 6e 5d } //1 [PageDown]
		$a_01_5 = {5b 53 63 72 6f 6c 6c 20 4c 6f 63 6b 5d } //1 [Scroll Lock]
		$a_01_6 = {5b 46 31 5d 00 00 00 00 5b 45 53 43 5d 00 } //1
		$a_01_7 = {57 69 6e 64 6f 77 73 20 54 69 74 6c 65 3a 25 73 } //1 Windows Title:%s
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}