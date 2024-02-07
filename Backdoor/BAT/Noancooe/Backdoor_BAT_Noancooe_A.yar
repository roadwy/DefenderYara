
rule Backdoor_BAT_Noancooe_A{
	meta:
		description = "Backdoor:BAT/Noancooe.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {4e 61 6e 6f 43 6f 72 65 20 43 6c 69 65 6e } //01 00  NanoCore Clien
		$a_03_1 = {1f 1d 12 00 1a 28 90 01 01 00 00 06 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_BAT_Noancooe_A_2{
	meta:
		description = "Backdoor:BAT/Noancooe.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {4e 61 6e 6f 43 6f 72 65 2e 65 78 65 } //01 00  NanoCore.exe
		$a_01_1 = {4c 56 5f 47 52 4f 55 50 00 48 65 61 64 65 72 73 00 42 61 73 65 43 6f 6d 6d 61 6e 64 00 } //01 00 
		$a_01_2 = {42 72 6f 6e 7a 65 00 53 69 6c 76 65 72 00 47 6f 6c 64 00 50 6c 61 74 69 6e 75 6d 00 44 69 61 6d 6f 6e 64 00 } //01 00  牂湯敺匀汩敶r潇摬倀慬楴畮m楄浡湯d
		$a_01_3 = {13 0e 11 0e 16 1f 58 9d 11 0e 17 1f 30 9d 11 0e 18 1f 58 9d 11 0e } //00 00 
		$a_00_4 = {78 bc } //00 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_BAT_Noancooe_A_3{
	meta:
		description = "Backdoor:BAT/Noancooe.A,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {4e 61 6e 6f 43 6f 72 65 20 43 6c 69 65 6e 74 2e 65 78 65 } //01 00  NanoCore Client.exe
		$a_01_1 = {43 6f 6e 6e 65 63 74 44 6f 6e 65 00 43 72 65 61 74 65 50 69 70 65 00 } //01 00 
		$a_01_2 = {42 61 73 65 43 6f 6d 6d 61 6e 64 00 44 65 62 75 67 54 79 70 65 00 46 69 6c 65 52 65 73 70 6f 6e 73 65 00 } //01 00 
		$a_01_3 = {46 69 6c 65 44 61 74 61 00 46 69 6c 65 44 6f 77 6e 6c 6f 61 64 00 } //01 00  楆敬慄慴䘀汩䑥睯汮慯d
		$a_01_4 = {48 6f 73 74 44 61 74 61 00 50 6c 75 67 69 6e 44 65 74 61 69 6c 73 00 50 6c 75 67 69 6e 44 61 74 61 00 } //0a 00  潈瑳慄慴倀畬楧䑮瑥楡獬倀畬楧䑮瑡a
		$a_01_5 = {06 1a 1f 0d 9c 06 1b 1f 15 9c 06 1c 1f 22 9c 06 1d 1f 37 9c } //00 00 
		$a_00_6 = {7e 15 00 00 7b 2a 2b be 44 e2 4e c0 23 5d 7b 2c 61 28 14 93 } //00 00 
	condition:
		any of ($a_*)
 
}