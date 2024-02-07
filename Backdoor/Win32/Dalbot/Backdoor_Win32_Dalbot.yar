
rule Backdoor_Win32_Dalbot{
	meta:
		description = "Backdoor:Win32/Dalbot,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {59 32 31 6b 4c 6d 56 34 5a 51 3d 3d } //01 00  Y21kLmV4ZQ==
		$a_01_1 = {59 7a 70 63 58 48 64 70 62 6d 52 76 64 33 4e 63 58 48 4e 35 63 33 52 6c 62 54 4d 79 58 46 78 6a 62 57 51 75 5a 58 68 6c } //01 00  YzpcXHdpbmRvd3NcXHN5c3RlbTMyXFxjbWQuZXhl
		$a_01_2 = {4c 65 61 76 65 20 53 65 6e 64 43 6f 6d 6d 61 6e 64 52 65 71 21 } //01 00  Leave SendCommandReq!
		$a_01_3 = {72 65 71 70 61 74 68 3d 00 } //01 00 
		$a_01_4 = {26 46 49 4c 45 43 4f 4e 54 45 4e 54 3d 00 } //01 00  䘦䱉䍅乏䕔呎=
		$a_01_5 = {63 00 6c 00 69 00 65 00 6e 00 74 00 70 00 61 00 74 00 68 00 } //01 00  clientpath
		$a_01_6 = {72 00 65 00 71 00 66 00 69 00 6c 00 65 00 70 00 61 00 74 00 68 00 } //01 00  reqfilepath
		$a_01_7 = {51 33 4a 6c 59 58 52 6c 55 48 4a 76 59 32 56 7a 63 30 45 3d } //01 00  Q3JlYXRlUHJvY2Vzc0E=
		$a_80_8 = {63 6c 69 65 6e 74 6b 65 79 } //clientkey  00 00 
	condition:
		any of ($a_*)
 
}