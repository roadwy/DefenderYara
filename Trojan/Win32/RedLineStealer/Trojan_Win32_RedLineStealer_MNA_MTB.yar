
rule Trojan_Win32_RedLineStealer_MNA_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.MNA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {62 5a 47 74 41 52 59 50 46 5c 41 65 57 47 35 } //01 00  bZGtARYPF\AeWG5
		$a_00_1 = {14 3c f6 69 5a 45 79 6d 7e 42 43 46 8a 97 64 70 fb 72 4d 62 76 69 73 74 33 55 34 71 4e 33 61 66 72 31 78 6e 37 4a 46 4e 49 56 31 75 6f 55 30 6a 6f 4b 59 59 39 44 65 42 6a 55 67 56 f2 67 79 4b } //01 00 
		$a_01_2 = {46 69 6e 64 4e 65 78 74 46 69 6c 65 57 } //01 00  FindNextFileW
		$a_01_3 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00  IsDebuggerPresent
		$a_01_4 = {4c 6f 63 6b 52 65 73 6f 75 72 63 65 } //01 00  LockResource
		$a_01_5 = {2e 35 62 69 31 6b 32 } //00 00  .5bi1k2
	condition:
		any of ($a_*)
 
}