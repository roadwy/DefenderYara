
rule Backdoor_Win32_Teevsock_H{
	meta:
		description = "Backdoor:Win32/Teevsock.H,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {73 71 6c 73 72 76 2e 65 78 65 } //1 sqlsrv.exe
		$a_03_1 = {89 08 89 50 04 8d 84 90 01 03 00 00 8b f0 8a 08 83 c0 01 84 c9 75 f7 8d bc 90 01 03 00 00 2b c6 83 c7 ff 8d a4 24 00 00 00 00 8a 4f 01 90 00 } //1
		$a_03_2 = {68 60 ea 00 00 ff 15 90 01 03 00 33 c9 33 c0 8a d1 80 c2 0d 30 90 90 90 01 03 00 83 f9 03 7e 04 33 c9 eb 03 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}