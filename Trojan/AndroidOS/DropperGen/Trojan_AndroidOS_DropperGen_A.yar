
rule Trojan_AndroidOS_DropperGen_A{
	meta:
		description = "Trojan:AndroidOS/DropperGen.A,SIGNATURE_TYPE_ELFHSTR_EXT,0b 00 0b 00 03 00 00 0a 00 "
		
	strings :
		$a_00_0 = {6e 66 79 71 75 2e 6a 61 72 } //01 00 
		$a_03_1 = {5e 49 02 22 79 44 90 01 03 ed 03 94 07 1c 00 28 90 00 } //01 00 
		$a_03_2 = {79 23 03 70 83 70 78 23 c3 70 73 23 03 71 6d 23 43 71 70 23 83 71 67 23 c3 71 76 23 03 72 6b 23 83 72 6a 23 68 22 c3 72 66 23 42 70 03 73 72 22 83 73 62 23 c3 73 80 21 42 72 42 73 04 aa 90 01 03 fd 11 20 90 01 03 ec 2d 4c 00 21 11 22 02 90 90 01 03 ec a8 1c 02 99 04 aa 90 01 03 f8 90 00 } //00 00 
		$a_00_3 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}