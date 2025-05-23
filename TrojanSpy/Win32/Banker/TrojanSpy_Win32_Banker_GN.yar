
rule TrojanSpy_Win32_Banker_GN{
	meta:
		description = "TrojanSpy:Win32/Banker.GN,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_02_0 = {00 43 3a 5c 41 72 71 75 69 76 6f 73 20 64 65 20 70 72 6f 67 72 61 6d 61 73 5c 90 12 08 00 2e 65 78 65 } //10
		$a_01_1 = {07 00 00 00 50 61 6e 64 6f 72 61 00 ff ff ff ff 03 00 00 00 52 75 6e 00 } //10
		$a_00_2 = {c3 00 00 00 63 3a 5c 5c 73 63 70 4d 49 42 2e 64 6c 6c 2c 20 73 63 70 49 42 43 66 67 2e 62 69 6e 2c 20 73 63 70 4c 49 42 2e 64 6c 6c 2c 20 73 63 70 73 73 73 68 32 2e 64 6c 6c 2c 20 73 73 68 69 62 2e 64 6c 6c 00 00 00 43 3a 5c 41 72 71 75 69 76 6f 73 20 64 65 20 70 72 6f 67 72 61 6d 61 73 5c 53 63 70 61 64 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_01_1  & 1)*10+(#a_00_2  & 1)*10) >=30
 
}