
rule TrojanSpy_Win32_Banker_ME{
	meta:
		description = "TrojanSpy:Win32/Banker.ME,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 65 64 62 2e 6c 6f 67 2e 74 78 74 2e 70 66 2e 6a 70 67 } //1 .edb.log.txt.pf.jpg
		$a_01_1 = {73 76 63 68 6f 73 74 2e 65 78 65 2c 73 6d 73 73 2e 65 78 65 2c 6c 73 61 73 73 2e 65 78 65 2c 73 65 72 76 69 63 65 73 2e 65 78 65 2c 77 69 6e 6c 6f 67 6f 6e 2e 65 78 65 } //1 svchost.exe,smss.exe,lsass.exe,services.exe,winlogon.exe
		$a_01_2 = {5c 68 6c 67 64 2e 64 6c 6c 00 } //1
		$a_01_3 = {5c 68 6c 67 64 2e 65 78 65 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}