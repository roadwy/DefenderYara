
rule Worm_BAT_Stealmog_A{
	meta:
		description = "Worm:BAT/Stealmog.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {57 65 62 73 69 74 65 42 6c 6f 63 6b 65 72 46 75 6e 63 74 00 } //02 00  敗獢瑩䉥潬正牥畆据t
		$a_01_1 = {4b 65 79 6c 6f 67 4f 6e 6c 79 53 65 6e 64 4d 61 69 6c 43 6f 6e 66 69 72 6d 61 74 69 6f 6e 00 } //01 00 
		$a_01_2 = {55 53 42 53 70 72 65 61 64 65 72 00 } //01 00  单卂牰慥敤r
		$a_01_3 = {49 73 49 74 49 6e 66 65 63 74 65 64 00 } //01 00 
		$a_01_4 = {67 65 74 5f 4a 70 65 67 00 } //00 00 
	condition:
		any of ($a_*)
 
}