
rule Backdoor_Win32_Unowvee_LOWFIB{
	meta:
		description = "Backdoor:Win32/Unowvee.LOWFIB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 00 4b 00 6e 00 6f 00 77 00 6e 00 44 00 6c 00 6c 00 73 00 33 00 32 00 5c 00 6e 00 74 00 64 00 6c 00 6c 00 2e 00 64 00 6c 00 6c 00 } //01 00  \KnownDlls32\ntdll.dll
		$a_01_1 = {5c 00 4b 00 6e 00 6f 00 77 00 6e 00 44 00 6c 00 6c 00 73 00 33 00 32 00 5c 00 6b 00 65 00 72 00 6e 00 65 00 6c 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 } //01 00  \KnownDlls32\kernel32.dll
		$a_01_2 = {5c 00 4b 00 6e 00 6f 00 77 00 6e 00 44 00 6c 00 6c 00 73 00 33 00 32 00 5c 00 63 00 72 00 79 00 70 00 74 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 } //01 00  \KnownDlls32\crypt32.dll
		$a_01_3 = {5c 00 4b 00 6e 00 6f 00 77 00 6e 00 44 00 6c 00 6c 00 73 00 5c 00 6e 00 74 00 64 00 6c 00 6c 00 2e 00 64 00 6c 00 6c 00 } //01 00  \KnownDlls\ntdll.dll
		$a_01_4 = {5c 00 4b 00 6e 00 6f 00 77 00 6e 00 44 00 6c 00 6c 00 73 00 5c 00 6b 00 65 00 72 00 6e 00 65 00 6c 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 } //01 00  \KnownDlls\kernel32.dll
		$a_01_5 = {5c 00 4b 00 6e 00 6f 00 77 00 6e 00 44 00 6c 00 6c 00 73 00 5c 00 63 00 72 00 79 00 70 00 74 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 } //00 00  \KnownDlls\crypt32.dll
	condition:
		any of ($a_*)
 
}