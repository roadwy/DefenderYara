
rule Trojan_Win32_Tofsee_Y{
	meta:
		description = "Trojan:Win32/Tofsee.Y,SIGNATURE_TYPE_PEHSTR_EXT,65 00 65 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //64 00 
		$a_03_1 = {76 2d 8b 55 08 0f b6 14 11 33 c2 8b d0 83 e2 0f c1 e8 04 33 04 90 01 05 8b d0 83 e2 0f c1 e8 04 33 04 90 01 05 41 3b 4d 0c 72 d3 f7 d0 5d c3 90 00 } //00 00 
		$a_00_2 = {5d 04 00 00 c6 00 05 80 5c 24 00 00 c7 00 05 80 00 00 01 00 08 00 0e 00 ac 21 54 6f 66 73 65 65 2e 59 21 73 6d 73 00 00 01 40 05 82 70 00 04 00 ce 09 00 00 bf ad ba 86 78 4e 00 00 7b 5d 04 00 00 c7 00 05 80 5c 34 00 00 c9 00 05 80 00 00 01 00 32 00 1e 00 52 61 6e 73 6f 6d 3a 57 69 6e 33 32 2f 53 74 } //6f 70 
	condition:
		any of ($a_*)
 
}