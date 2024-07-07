
rule PWS_Win32_Sinowal_AJ{
	meta:
		description = "PWS:Win32/Sinowal.AJ,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0a 00 07 00 00 "
		
	strings :
		$a_01_0 = {0f af 4d b4 89 4d ac ff 75 ec 5a 3b 55 ac } //1
		$a_01_1 = {5a 66 89 0a 8b 45 b0 c1 e0 03 ff 75 a8 59 } //1
		$a_01_2 = {8b 8d 78 ff ff ff d1 e1 2b c1 83 e8 02 } //1
		$a_00_3 = {66 64 73 6b 73 64 2e 70 64 62 } //10 fdsksd.pdb
		$a_00_4 = {00 70 64 62 2e 70 64 62 00 } //10
		$a_00_5 = {34 66 62 64 73 76 39 38 34 6f 2e 70 64 62 } //10 4fbdsv984o.pdb
		$a_00_6 = {6d 73 64 74 63 64 62 67 64 62 67 2e 70 64 62 } //10 msdtcdbgdbg.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*10+(#a_00_4  & 1)*10+(#a_00_5  & 1)*10+(#a_00_6  & 1)*10) >=10
 
}