
rule TrojanDropper_Win32_Evotob_gen_A{
	meta:
		description = "TrojanDropper:Win32/Evotob.gen!A,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {22 25 25 77 69 6e 64 69 72 25 25 5c 73 79 73 74 65 6d 33 32 5c 73 64 62 69 6e 73 74 2e 65 78 65 22 20 2f 71 20 2f 75 20 22 25 73 22 00 } //1
		$a_01_1 = {5c 57 69 6e 64 6f 77 73 20 44 65 66 65 6e 64 65 72 5c 45 78 63 6c 75 73 69 6f 6e 73 5c 50 72 6f 63 65 73 73 65 73 20 20 22 20 2f 76 20 73 76 63 68 6f 73 74 2e 65 78 65 20 2f 74 20 20 52 45 47 5f 44 57 4f 52 44 20 2f 64 20 30 } //1 \Windows Defender\Exclusions\Processes  " /v svchost.exe /t  REG_DWORD /d 0
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}