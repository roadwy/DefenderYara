
rule Trojan_Win32_CryptTrickload_B_MTB{
	meta:
		description = "Trojan:Win32/CryptTrickload.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_03_0 = {2e 70 68 70 3f 73 69 3d 90 02 10 26 6b 6f 3d 90 02 10 26 63 76 3d 90 02 20 2c 20 22 66 61 6c 73 65 22 29 3b 90 00 } //1
		$a_81_1 = {40 40 57 69 6e 64 6f 77 73 20 44 65 66 65 6e 64 65 72 3a 3a 25 50 72 6f 67 72 61 6d 46 69 6c 65 73 25 5c 57 69 6e 64 6f 77 73 20 44 65 66 65 6e 64 65 72 5c 4d 73 4d 70 65 6e 67 2e 65 78 65 40 40 } //1 @@Windows Defender::%ProgramFiles%\Windows Defender\MsMpeng.exe@@
		$a_03_2 = {2e 6f 70 65 6e 28 22 47 45 54 22 2c 20 22 68 74 74 70 73 3a 2f 2f 90 02 20 2f 90 02 10 2f 90 02 15 2e 70 68 70 90 00 } //1
		$a_81_3 = {2e 45 78 65 63 51 75 65 72 79 28 22 53 65 6c 65 63 74 20 2a 20 66 72 6f 6d 20 57 69 6e 33 32 5f 4e 65 74 77 6f 72 6b 41 64 61 70 74 65 72 43 6f 6e 66 69 67 75 72 61 74 69 6f 6e 20 57 68 65 72 65 20 49 50 45 6e 61 62 6c 65 64 3d 54 52 55 45 22 29 3b } //1 .ExecQuery("Select * from Win32_NetworkAdapterConfiguration Where IPEnabled=TRUE");
		$a_81_4 = {2e 45 78 65 63 51 75 65 72 79 28 22 53 65 6c 65 63 74 20 44 6f 6d 61 69 6e 52 6f 6c 65 20 66 72 6f 6d 20 57 69 6e 33 32 5f 43 6f 6d 70 75 74 65 72 53 79 73 74 65 6d 22 29 3b } //1 .ExecQuery("Select DomainRole from Win32_ComputerSystem");
		$a_81_5 = {2e 45 78 65 63 51 75 65 72 79 28 22 53 65 6c 65 63 74 20 2a 20 66 72 6f 6d 20 41 6e 74 69 56 69 72 75 73 50 72 6f 64 75 63 74 22 29 3b } //1 .ExecQuery("Select * from AntiVirusProduct");
		$a_81_6 = {2e 45 78 70 61 6e 64 45 6e 76 69 72 6f 6e 6d 65 6e 74 53 74 72 69 6e 67 73 28 22 25 54 45 4d 50 25 22 29 3b } //1 .ExpandEnvironmentStrings("%TEMP%");
		$a_03_7 = {2e 53 6c 65 65 70 28 22 90 02 10 22 29 3b 90 00 } //1
		$a_81_8 = {77 73 63 72 69 70 74 20 20 2f 65 3a 4a 53 63 72 69 70 74 } //1 wscript  /e:JScript
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1+(#a_03_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_03_7  & 1)*1+(#a_81_8  & 1)*1) >=9
 
}