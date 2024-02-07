
rule Trojan_Win32_Cinmus_H{
	meta:
		description = "Trojan:Win32/Cinmus.H,SIGNATURE_TYPE_PEHSTR,08 00 08 00 05 00 00 05 00 "
		
	strings :
		$a_01_0 = {5c 44 72 69 76 65 72 5c 6f 62 6a 66 72 65 5c 69 33 38 36 5c 61 63 70 69 64 69 73 6b 2e 70 64 62 } //02 00  \Driver\objfre\i386\acpidisk.pdb
		$a_01_1 = {57 69 6e 64 6f 77 73 20 44 72 69 76 65 72 20 4d 61 6e 61 67 65 72 20 52 75 6e 6e 69 6e 67 20 25 73 21 } //01 00  Windows Driver Manager Running %s!
		$a_01_2 = {57 69 6e 64 6f 77 73 20 53 79 73 74 65 6d 20 44 72 69 76 65 72 20 53 74 61 72 74 65 64 21 } //01 00  Windows System Driver Started!
		$a_01_3 = {47 65 74 53 79 73 74 65 6d 44 69 72 65 63 74 6f 72 79 57 } //01 00  GetSystemDirectoryW
		$a_01_4 = {50 73 4c 6f 6f 6b 75 70 50 72 6f 63 65 73 73 42 79 50 72 6f 63 65 73 73 49 64 } //00 00  PsLookupProcessByProcessId
	condition:
		any of ($a_*)
 
}