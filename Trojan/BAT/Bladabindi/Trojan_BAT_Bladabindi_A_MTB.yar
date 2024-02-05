
rule Trojan_BAT_Bladabindi_A_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {53 79 73 74 65 6d 20 45 78 70 6f 72 65 72 2e 70 64 62 } //01 00 
		$a_81_1 = {24 36 39 36 65 32 64 33 30 2d 61 31 66 61 2d 34 38 31 35 2d 38 30 37 31 2d 37 35 37 38 38 33 33 36 62 33 61 33 } //01 00 
		$a_81_2 = {55 33 6c 7a 64 47 56 74 49 45 56 34 63 47 39 79 5a 58 49 6b } //01 00 
		$a_81_3 = {50 64 66 66 66 64 77 77 66 64 77 64 77 66 66 64 64 66 66 77 77 66 64 } //01 00 
		$a_81_4 = {3a 70 72 6f 63 65 73 73 73 73 68 61 63 6b 65 72 72 72 72 72 72 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Bladabindi_A_MTB_2{
	meta:
		description = "Trojan:BAT/Bladabindi.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 00 69 00 72 00 77 00 6d 00 61 00 72 00 65 00 5c 00 61 00 6e 00 61 00 6e 00 2e 00 74 00 78 00 74 00 } //01 00 
		$a_01_1 = {46 00 69 00 72 00 77 00 6d 00 61 00 72 00 65 00 5c 00 63 00 73 00 61 00 70 00 70 00 33 00 2e 00 65 00 78 00 65 00 } //01 00 
		$a_01_2 = {53 6f 75 72 63 65 5c 52 65 70 6f 73 5c 64 65 70 6c 6f 79 5c 64 65 70 6c 6f 79 5c 6f 62 6a 5c 44 65 62 75 67 5c 64 65 70 6c 6f 79 2e 70 64 62 } //01 00 
		$a_01_3 = {57 69 6e 64 6f 77 73 20 55 53 42 20 53 65 72 76 69 73 69 } //01 00 
		$a_01_4 = {24 31 38 36 36 35 35 39 34 2d 66 36 65 34 2d 34 61 64 38 2d 61 35 33 31 2d 39 64 30 61 30 30 35 32 30 30 32 35 } //01 00 
		$a_01_5 = {42 00 75 00 20 00 44 00 69 00 73 00 6b 00 } //01 00 
		$a_01_6 = {55 00 53 00 42 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 2e 00 65 00 78 00 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Bladabindi_A_MTB_3{
	meta:
		description = "Trojan:BAT/Bladabindi.A!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 01 00 00 03 00 "
		
	strings :
		$a_01_0 = {e0 a4 96 e0 a4 a6 e0 a4 9a e0 a4 8b e0 a4 94 e0 a4 8f e0 a4 8f e0 a4 aa e0 a4 9a e0 a4 b7 e0 a4 a6 e0 a4 8f e0 a4 96 e0 a4 98 e0 a4 87 e0 a4 8f e0 a4 af e0 a4 a1 e0 a4 87 e0 a4 a8 e0 a4 aa e0 a4 ac e0 a4 ae e0 a4 9f e0 a4 b7 e0 a4 ad e0 a4 97 e0 a4 a3 e0 a4 a8 e0 a4 af 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}