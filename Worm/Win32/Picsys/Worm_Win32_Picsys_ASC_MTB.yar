
rule Worm_Win32_Picsys_ASC_MTB{
	meta:
		description = "Worm:Win32/Picsys.ASC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 69 73 74 66 75 63 6b 69 6e 67 20 61 6e 64 20 68 6f 77 20 69 64 65 20 69 74 20 67 6f 65 73 2e 6d 70 67 2e 70 69 66 } //01 00  fistfucking and how ide it goes.mpg.pif
		$a_01_1 = {6e 79 6d 70 68 20 65 6e 6a 6f 79 73 20 66 69 73 74 69 6e 67 20 61 6c 6c 20 74 68 65 20 77 61 79 20 74 6f 20 74 68 65 20 65 6c 62 6f 77 2e 6d 70 67 2e 70 69 66 } //01 00  nymph enjoys fisting all the way to the elbow.mpg.pif
		$a_01_2 = {62 6c 6f 6e 64 65 20 62 61 62 65 20 68 61 6e 64 66 75 63 6b 69 6e 67 20 68 65 72 73 65 6c 66 2e 6d 70 67 2e 70 69 66 } //01 00  blonde babe handfucking herself.mpg.pif
		$a_01_3 = {73 65 78 79 20 62 69 20 67 75 79 73 20 64 6f 69 6e 67 20 61 20 63 68 69 63 6b 20 74 6f 67 65 74 68 65 72 2e 6d 70 67 2e 70 69 66 } //01 00  sexy bi guys doing a chick together.mpg.pif
		$a_01_4 = {62 6c 6f 6e 64 65 20 73 75 63 6b 69 6e 67 20 61 6e 64 20 66 75 63 6b 73 20 6f 75 74 64 6f 6f 72 2e 6d 70 67 2e 70 69 66 } //01 00  blonde sucking and fucks outdoor.mpg.pif
		$a_01_5 = {73 65 78 79 20 66 75 63 6b 65 64 20 74 72 61 6e 6e 79 20 62 61 62 65 2e 6d 70 67 2e 70 69 66 } //01 00  sexy fucked tranny babe.mpg.pif
		$a_01_6 = {62 65 61 75 74 69 66 75 6c 20 62 61 62 65 73 20 65 78 74 65 6e 64 69 6e 67 20 6c 6f 76 65 20 61 6e 64 20 63 6f 6d 70 61 73 73 69 6f 6e 2e 6d 70 67 2e 70 69 66 } //01 00  beautiful babes extending love and compassion.mpg.pif
		$a_01_7 = {74 65 65 6e 20 68 6f 74 74 69 65 20 67 65 74 69 6e 67 20 62 75 74 74 66 75 63 6b 65 64 2e 6d 70 67 2e 70 69 66 } //00 00  teen hottie geting buttfucked.mpg.pif
	condition:
		any of ($a_*)
 
}