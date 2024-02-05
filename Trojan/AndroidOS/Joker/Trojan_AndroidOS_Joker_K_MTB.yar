
rule Trojan_AndroidOS_Joker_K_MTB{
	meta:
		description = "Trojan:AndroidOS/Joker.K!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_00_0 = {1a 00 39 09 6e 20 f6 09 05 00 0c 05 21 50 12 01 35 01 32 00 46 02 05 01 6e 10 01 0a 02 00 0c 03 1a 04 bc 27 6e 20 f7 09 43 00 0a 03 38 03 21 00 1a 03 6c 09 6e 20 f6 09 32 00 0c 02 21 23 12 14 37 43 17 00 46 05 02 04 6e 10 01 0a 05 00 0c 05 1a 00 00 00 1a 01 3d 03 6e 30 f5 09 15 00 0c 05 1a 01 b5 04 6e 30 f5 09 15 00 0c 05 11 05 d8 01 01 01 28 cf 12 05 11 05 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_AndroidOS_Joker_K_MTB_2{
	meta:
		description = "Trojan:AndroidOS/Joker.K!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {12 1c 12 0b 12 29 23 94 90 01 02 71 20 90 01 02 fd 00 0c 09 4d 09 04 0b 71 20 90 01 02 fe 00 0c 09 4d 09 04 0c 46 09 04 0b 6e 10 90 01 02 09 00 0c 09 1a 0a 40 00 6e 20 90 01 02 a9 00 0c 00 6e 20 90 01 02 c0 00 46 09 04 0b 71 20 90 01 02 09 00 0c 07 90 00 } //02 00 
		$a_03_1 = {12 20 23 00 2d 00 71 20 90 01 02 ec 00 0c 01 12 02 4d 01 00 02 71 20 90 01 02 ed 00 0c 01 12 13 4d 01 00 03 46 01 00 02 6e 10 90 01 02 01 00 0c 01 1a 04 69 00 6e 20 90 01 02 41 00 0c 01 6e 20 90 01 02 31 00 46 01 00 02 46 05 00 02 6e 10 90 01 02 05 00 0c 05 6e 20 90 01 02 45 00 0c 05 71 20 90 01 02 51 00 0c 01 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}