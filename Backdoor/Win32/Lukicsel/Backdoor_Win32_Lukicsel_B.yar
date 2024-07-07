
rule Backdoor_Win32_Lukicsel_B{
	meta:
		description = "Backdoor:Win32/Lukicsel.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {7c 0f 43 e8 90 01 04 32 06 88 07 46 47 4b 75 f2 90 00 } //1
		$a_01_1 = {49 50 31 00 ff ff ff ff 05 00 00 00 50 6f 72 74 31 00 } //1
		$a_01_2 = {49 50 32 00 ff ff ff ff 05 00 00 00 50 6f 72 74 32 00 } //1
		$a_01_3 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 41 63 74 69 76 65 20 53 65 74 75 70 5c 44 61 74 61 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}