
rule Worm_Win32_Voterai_H{
	meta:
		description = "Worm:Win32/Voterai.H,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 61 69 6c 61 4f 2e 65 78 65 } //01 00 
		$a_01_1 = {5c 52 61 69 6c 61 20 4f 64 69 6e 67 61 2e 65 78 65 } //01 00 
		$a_01_2 = {52 61 69 6c 61 20 4f 64 69 6e 67 61 2e 67 69 66 } //01 00 
		$a_01_3 = {25 5c 64 72 69 76 65 72 73 5c } //01 00 
		$a_01_4 = {5c 61 75 74 6f 72 75 6e 2e 69 6e 66 } //00 00 
	condition:
		any of ($a_*)
 
}