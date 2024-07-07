
rule TrojanSpy_Win64_KeyLogger_SK_MTB{
	meta:
		description = "TrojanSpy:Win64/KeyLogger.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 5c 57 69 6e 53 79 73 4d 61 6e 61 67 65 72 2e 65 78 65 } //2 \Microsoft\Windows\Start Menu\Programs\Startup\WinSysManager.exe
		$a_01_1 = {44 3a 77 69 6e 6c 6f 67 73 2e 74 78 74 } //2 D:winlogs.txt
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}