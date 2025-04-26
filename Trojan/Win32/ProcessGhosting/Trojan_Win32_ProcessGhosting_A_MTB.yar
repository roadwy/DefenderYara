
rule Trojan_Win32_ProcessGhosting_A_MTB{
	meta:
		description = "Trojan:Win32/ProcessGhosting.A!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {70 72 6f 63 65 73 73 2d 67 68 6f 73 74 69 6e 67 } //1 process-ghosting
		$a_01_1 = {41 64 6a 75 73 74 54 6f 6b 65 6e 50 72 69 76 69 6c 65 67 65 73 } //1 AdjustTokenPrivileges
		$a_01_2 = {48 83 ec 30 48 8b d9 4c 8b f2 48 8b 53 18 4c 8d 7b 18 48 8b 49 10 48 8b c2 48 2b c1 45 33 ed 48 83 f8 09 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}