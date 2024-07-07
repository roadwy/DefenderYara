
rule Backdoor_Win64_TinyTurla_RHB_MTB{
	meta:
		description = "Backdoor:Win64/TinyTurla.RHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 08 00 00 "
		
	strings :
		$a_01_0 = {6f 75 74 2e 64 6c 6c 00 53 65 72 76 69 63 65 4d 61 69 6e } //1
		$a_03_1 = {2f 72 73 73 90 01 01 6f 6c 64 2e 70 68 70 90 00 } //1
		$a_01_2 = {6b 69 6c 6c 6d 65 } //1 killme
		$a_01_3 = {45 6e 64 70 6f 69 6e 74 20 63 68 61 6e 67 65 64 } //1 Endpoint changed
		$a_01_4 = {43 6c 69 65 6e 74 20 52 65 61 64 79 } //1 Client Ready
		$a_01_5 = {6c 75 2e 62 61 74 } //1 lu.bat
		$a_01_6 = {64 65 6c 6b 69 6c 6c 20 2f 46 } //1 delkill /F
		$a_03_7 = {50 45 00 00 64 86 07 90 01 11 0b 02 0e 1d 00 e4 02 00 00 a8 01 00 00 00 00 00 90 01 02 01 90 00 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_03_7  & 1)*2) >=9
 
}