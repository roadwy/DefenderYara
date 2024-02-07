
rule Backdoor_BAT_Noancooe_A_{
	meta:
		description = "Backdoor:BAT/Noancooe.A!!Noancooe.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,16 00 16 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {06 1a 1f 0d 9c 06 1b 1f 15 9c 06 1c 1f 22 9c 06 1d 1f 37 9c } //0a 00 
		$a_01_1 = {4e 61 6e 6f 43 6f 72 65 20 43 6c 69 65 6e 74 2e 65 78 65 } //01 00  NanoCore Client.exe
		$a_01_2 = {43 6f 6e 6e 65 63 74 44 6f 6e 65 00 43 72 65 61 74 65 50 69 70 65 00 } //01 00 
		$a_01_3 = {42 61 73 65 43 6f 6d 6d 61 6e 64 00 44 65 62 75 67 54 79 70 65 00 46 69 6c 65 52 65 73 70 6f 6e 73 65 00 } //01 00 
		$a_01_4 = {46 69 6c 65 44 61 74 61 00 46 69 6c 65 44 6f 77 6e 6c 6f 61 64 00 } //01 00  楆敬慄慴䘀汩䑥睯汮慯d
		$a_01_5 = {48 6f 73 74 44 61 74 61 00 50 6c 75 67 69 6e 44 65 74 61 69 6c 73 00 50 6c 75 67 69 6e 44 61 74 61 00 } //00 00  潈瑳慄慴倀畬楧䑮瑥楡獬倀畬楧䑮瑡a
	condition:
		any of ($a_*)
 
}