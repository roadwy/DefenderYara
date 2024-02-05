
rule TrojanDropper_Win32_Maran_AU{
	meta:
		description = "TrojanDropper:Win32/Maran.AU,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {56 6f 69 63 65 4d 61 6e 61 67 65 72 44 6f 77 6e } //01 00 
		$a_01_1 = {5c 6f 64 33 6d 64 69 2e 64 6c 6c } //01 00 
		$a_01_2 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30 } //01 00 
		$a_01_3 = {61 76 70 2e 65 78 65 } //01 00 
		$a_01_4 = {64 65 6c 70 6c 6d 65 2e 62 61 74 00 ff ff ff ff 09 00 00 00 40 65 63 68 6f 20 6f 66 66 00 00 00 ff ff ff ff 05 00 00 00 3a 6c 6f 6f 70 00 00 00 ff ff ff ff 05 00 00 00 64 65 6c 20 22 00 00 00 } //01 00 
		$a_01_5 = {07 00 00 00 77 69 6e 78 70 6e 70 00 ff ff ff ff 03 00 00 00 65 78 65 00 ff ff ff ff 01 00 00 00 5c 00 00 00 41 75 64 69 6f 20 41 64 61 70 74 65 72 00 00 00 56 47 41 44 6f 77 6e 00 } //00 00 
	condition:
		any of ($a_*)
 
}