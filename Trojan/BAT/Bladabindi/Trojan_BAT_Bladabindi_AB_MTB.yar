
rule Trojan_BAT_Bladabindi_AB_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {72 e3 00 00 70 72 bf 00 00 70 6f 90 01 03 0a 00 73 4a 00 00 0a 0d 09 6f 90 01 03 0a 72 bf 00 00 70 6f 90 01 03 0a 00 09 6f 90 00 } //01 00 
		$a_01_1 = {7a 00 69 00 72 00 6f 00 6c 00 61 00 6e 00 64 00 20 00 67 00 61 00 6d 00 65 00 2e 00 65 00 78 00 65 00 } //00 00  ziroland game.exe
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Bladabindi_AB_MTB_2{
	meta:
		description = "Trojan:BAT/Bladabindi.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 0f 00 00 0a 0d 09 06 1f 10 6f 10 00 00 0a 6f 11 00 00 0a 09 06 1f 10 6f 10 00 00 0a 6f 12 00 00 0a 09 6f 13 00 00 0a 02 16 02 8e 69 6f 14 00 00 0a 0b 07 8e 69 1f 11 da 17 d6 8d 06 00 00 01 0c 07 1f 10 08 16 07 8e 69 1f 10 da 28 15 00 00 0a 08 2a } //01 00 
		$a_01_1 = {47 65 74 42 79 74 65 73 } //00 00  GetBytes
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Bladabindi_AB_MTB_3{
	meta:
		description = "Trojan:BAT/Bladabindi.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 06 00 00 0a 00 "
		
	strings :
		$a_00_0 = {fa 25 33 00 16 00 00 01 00 00 00 b9 00 00 00 3a 00 00 00 d7 00 00 00 02 03 00 00 08 01 00 00 74 01 00 00 13 00 00 00 07 01 00 00 01 00 00 00 02 00 00 00 4c 00 00 00 0f 00 00 00 44 } //03 00 
		$a_80_1 = {73 65 74 5f 55 73 65 53 79 73 74 65 6d 50 61 73 73 77 6f 72 64 43 68 61 72 } //set_UseSystemPasswordChar  03 00 
		$a_80_2 = {52 75 6e 57 6f 72 6b 65 72 43 6f 6d 70 6c 65 74 65 64 45 76 65 6e 74 48 61 6e 64 6c 65 72 } //RunWorkerCompletedEventHandler  03 00 
		$a_80_3 = {54 72 61 63 6b 44 65 63 72 50 72 6d 4b 65 79 } //TrackDecrPrmKey  03 00 
		$a_80_4 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //DownloadFile  03 00 
		$a_80_5 = {64 6f 77 6e 6c 6f 61 64 5f 6c 69 6e 6b } //download_link  00 00 
	condition:
		any of ($a_*)
 
}