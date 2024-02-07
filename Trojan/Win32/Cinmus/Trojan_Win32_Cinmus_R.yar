
rule Trojan_Win32_Cinmus_R{
	meta:
		description = "Trojan:Win32/Cinmus.R,SIGNATURE_TYPE_PEHSTR,09 00 09 00 06 00 00 04 00 "
		
	strings :
		$a_01_0 = {6c 6f 61 64 65 72 5c 44 72 69 76 65 72 5c 6f 62 6a 66 72 65 5c 69 33 38 36 5c 61 70 63 64 6c 69 2e 70 64 62 } //02 00  loader\Driver\objfre\i386\apcdli.pdb
		$a_01_1 = {61 00 70 00 63 00 64 00 6c 00 69 00 } //02 00  apcdli
		$a_01_2 = {65 78 70 6c 6f 72 65 72 2e 65 78 65 00 00 00 00 57 69 6e 64 6f 77 73 20 53 79 73 74 65 6d 20 44 72 69 76 65 72 20 53 74 61 72 74 65 64 21 } //01 00 
		$a_01_3 = {5a 77 51 75 65 72 79 49 6e 66 6f 72 6d 61 74 69 6f 6e 46 69 6c 65 } //01 00  ZwQueryInformationFile
		$a_01_4 = {4b 65 55 6e 73 74 61 63 6b 44 65 74 61 63 68 50 72 6f 63 65 73 73 } //01 00  KeUnstackDetachProcess
		$a_01_5 = {52 74 6c 51 75 65 72 79 52 65 67 69 73 74 72 79 56 61 6c 75 65 73 } //00 00  RtlQueryRegistryValues
	condition:
		any of ($a_*)
 
}