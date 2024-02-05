
rule Virus_Win16_Thus_gen_A{
	meta:
		description = "Virus:Win16/Thus.gen!A,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {27 54 68 75 73 5f 30 30 31 27 } //01 00 
		$a_00_1 = {27 41 6e 74 69 2d 53 6d 79 73 65 72 27 } //00 00 
	condition:
		any of ($a_*)
 
}