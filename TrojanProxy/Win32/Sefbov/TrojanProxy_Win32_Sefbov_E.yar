
rule TrojanProxy_Win32_Sefbov_E{
	meta:
		description = "TrojanProxy:Win32/Sefbov.E,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 44 45 46 41 55 4c 54 5c 53 6f 66 74 77 61 72 65 5c 41 4d 53 65 72 76 69 63 65 5c 43 61 6c 6c 42 61 63 6b } //01 00 
		$a_01_1 = {43 68 65 63 6b 50 6f 72 74 32 35 52 65 73 75 6c 74 } //01 00 
		$a_01_2 = {65 78 65 63 75 74 65 50 72 65 64 65 66 69 6e 65 64 51 75 65 72 79 3a } //00 00 
	condition:
		any of ($a_*)
 
}