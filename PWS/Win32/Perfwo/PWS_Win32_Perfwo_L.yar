
rule PWS_Win32_Perfwo_L{
	meta:
		description = "PWS:Win32/Perfwo.L,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {ff ff ff ff 0e 00 00 00 61 75 74 6f 75 70 64 61 74 65 2e 65 78 65 00 00 ff ff ff ff 0c 00 00 00 61 76 63 6f 6e 73 6f 6c 2e 65 78 65 00 00 00 00 ff ff ff ff 09 00 00 00 61 76 65 33 32 2e 65 78 65 00 } //01 00 
		$a_01_1 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //01 00 
		$a_01_2 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 } //01 00 
		$a_00_3 = {64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 } //01 00 
		$a_00_4 = {2a 2a 5f 5f 4c 32 73 70 79 5f 5f 2a 2a } //00 00 
	condition:
		any of ($a_*)
 
}