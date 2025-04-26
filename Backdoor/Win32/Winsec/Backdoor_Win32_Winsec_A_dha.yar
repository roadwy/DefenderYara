
rule Backdoor_Win32_Winsec_A_dha{
	meta:
		description = "Backdoor:Win32/Winsec.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {0f b6 77 ff 4f c1 e2 08 0b d6 4b f6 c3 03 75 05 83 e8 04 89 10 } //2
		$a_01_1 = {80 3f 00 74 10 8a 07 3c 2e 74 07 3c 20 74 03 88 03 43 } //2
		$a_01_2 = {2e 47 65 2e 74 45 2e 78 69 20 74 43 2e 6f 64 20 65 50 2e 20 72 6f 63 20 65 2e 73 73 00 } //1
		$a_01_3 = {9f 98 c6 b8 fc 20 24 cf 91 a7 73 01 d5 66 d3 31 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2) >=5
 
}