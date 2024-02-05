
rule TrojanSpy_AndroidOS_Pegasus_A{
	meta:
		description = "TrojanSpy:AndroidOS/Pegasus.A,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 64 61 74 61 2f 64 61 74 61 2f 63 6f 6d 2e 6e 65 74 77 6f 72 6b 2e 61 6e 64 72 6f 69 64 2f 2e 63 6f 6c 64 62 6f 6f 74 5f 69 6e 69 74 } //01 00 
		$a_00_1 = {2f 73 79 73 74 65 6d 2f 63 73 6b 20 22 63 68 6d 6f 64 20 37 31 31 20 2f 6d 6e 74 2f 6f 62 62 2f 2e 63 6f 6c 64 62 6f 6f 74 5f 69 6e 69 74 } //01 00 
		$a_00_2 = {2f 61 64 69 6e 66 6f 3f 67 69 3d 25 73 26 62 66 3d 25 73 } //00 00 
		$a_00_3 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}