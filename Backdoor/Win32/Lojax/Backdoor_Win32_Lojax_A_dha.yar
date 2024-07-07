
rule Backdoor_Win32_Lojax_A_dha{
	meta:
		description = "Backdoor:Win32/Lojax.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,28 00 28 00 05 00 00 "
		
	strings :
		$a_00_0 = {50 8a 00 34 b5 88 06 58 46 40 e2 f4 } //10
		$a_03_1 = {6a 04 be 00 10 00 00 56 56 6a 00 53 ff 15 90 01 04 8b f8 85 ff 74 40 6a 00 ff 75 08 ff 15 90 01 04 40 50 ff 75 08 57 53 ff 15 90 00 } //10
		$a_00_2 = {53 79 73 74 65 6d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 72 70 63 6e 65 74 70 } //10 System\CurrentControlSet\Services\rpcnetp
		$a_00_3 = {72 70 63 6e 65 74 70 2e 65 78 65 } //10 rpcnetp.exe
		$a_03_4 = {68 3f 00 0f 00 33 f6 56 ff 35 90 01 04 68 02 00 00 80 ff 15 18 10 40 00 90 00 } //10
	condition:
		((#a_00_0  & 1)*10+(#a_03_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_03_4  & 1)*10) >=40
 
}