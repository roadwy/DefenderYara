
rule Trojan_Win32_Amadey_SPH_MTB{
	meta:
		description = "Trojan:Win32/Amadey.SPH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {4f 50 6d 6f 51 61 42 77 4d 4e 37 32 51 65 79 51 52 75 3d 3d } //01 00 
		$a_01_1 = {4c 52 58 49 57 4d 43 51 55 66 62 44 58 50 6e 76 4f 4b 3d 3d } //01 00 
		$a_01_2 = {30 59 4b 53 33 4e 4e 33 4d 79 49 66 52 72 3d 3d } //01 00 
		$a_01_3 = {64 59 37 61 34 4f 4b 34 4c 68 59 31 34 4c 3d 3d } //01 00 
		$a_01_4 = {4b 65 43 62 4f 20 75 30 61 52 34 69 67 59 4c 51 4e 78 79 39 42 66 4e 65 4f 78 54 73 42 77 3d 3d } //00 00 
	condition:
		any of ($a_*)
 
}