
rule Trojan_Win64_KillAV_A_MTB{
	meta:
		description = "Trojan:Win64/KillAV.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {5c 2e 5c 50 52 4f 43 45 58 50 31 35 32 } //02 00  \.\PROCEXP152
		$a_01_1 = {45 78 63 65 70 74 20 69 6e 20 4b 69 6c 6c 50 72 6f 63 65 73 73 48 61 6e 64 6c 65 73 } //02 00  Except in KillProcessHandles
		$a_01_2 = {44 65 76 69 63 65 49 6f 43 6f 6e 74 72 6f 6c 20 74 6f 20 44 72 69 76 65 72 } //00 00  DeviceIoControl to Driver
	condition:
		any of ($a_*)
 
}