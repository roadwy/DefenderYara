
rule Backdoor_Win32_Bioazih_B_dha{
	meta:
		description = "Backdoor:Win32/Bioazih.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {61 00 72 00 65 00 20 00 79 00 6f 00 75 00 20 00 74 00 68 00 65 00 72 00 65 00 3f 00 20 00 00 00 } //1
		$a_01_1 = {65 78 69 74 0a 00 } //1
		$a_03_2 = {68 fc 0f 00 00 8d 45 0c 6a 00 50 e8 90 01 04 46 8d 85 90 01 04 6b f6 2c 56 50 8d 45 0c 50 e8 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
rule Backdoor_Win32_Bioazih_B_dha_2{
	meta:
		description = "Backdoor:Win32/Bioazih.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 04 00 00 "
		
	strings :
		$a_01_0 = {64 00 73 00 73 00 65 00 6d 00 68 00 2e 00 64 00 6c 00 6c 00 } //2 dssemh.dll
		$a_01_1 = {73 00 75 00 63 00 63 00 65 00 73 00 73 00 20 00 74 00 6f 00 20 00 6b 00 69 00 6c 00 6c 00 20 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 } //2 success to kill process
		$a_01_2 = {74 00 68 00 65 00 20 00 66 00 69 00 6c 00 65 00 20 00 72 00 65 00 63 00 76 00 20 00 65 00 72 00 72 00 6f 00 72 00 } //2 the file recv error
		$a_01_3 = {73 00 75 00 63 00 63 00 65 00 73 00 73 00 20 00 74 00 6f 00 20 00 64 00 65 00 6c 00 65 00 74 00 65 00 20 00 66 00 69 00 6c 00 65 00 66 00 6f 00 72 00 64 00 65 00 72 00 } //3 success to delete fileforder
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*3) >=9
 
}