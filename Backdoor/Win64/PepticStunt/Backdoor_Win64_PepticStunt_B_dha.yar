
rule Backdoor_Win64_PepticStunt_B_dha{
	meta:
		description = "Backdoor:Win64/PepticStunt.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 83 fb 07 0f 85 2e 02 00 00 41 81 39 65 78 65 63 0f 85 06 01 00 00 66 41 81 79 04 75 74 0f 85 f9 00 00 00 41 80 79 06 65 0f 85 ee 00 00 00 } //1
		$a_01_1 = {48 83 fb 08 0f 85 48 02 00 00 49 ba 73 65 6e 64 66 69 6c 65 } //1
		$a_01_2 = {41 81 39 67 65 74 66 0f 85 60 03 00 00 66 41 81 79 04 69 6c 0f 85 53 03 00 00 41 80 79 06 65 0f 85 48 03 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}