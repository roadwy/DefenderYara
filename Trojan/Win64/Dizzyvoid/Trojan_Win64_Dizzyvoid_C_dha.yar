
rule Trojan_Win64_Dizzyvoid_C_dha{
	meta:
		description = "Trojan:Win64/Dizzyvoid.C!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 74 74 70 41 64 64 55 72 6c 20 66 61 69 6c 65 64 20 77 69 74 68 20 25 6c 75 } //01 00  HttpAddUrl failed with %lu
		$a_01_1 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 74 65 6d 70 5c 66 6f 6e 74 2e 74 6d 70 } //01 00  c:\windows\temp\font.tmp
		$a_01_2 = {4d 61 70 56 69 65 77 4f 66 46 69 6c 65 20 66 61 69 6c 65 64 2e 5b 25 64 5d } //01 00  MapViewOfFile failed.[%d]
		$a_01_3 = {49 74 27 73 20 4e 6f 74 20 50 45 20 46 69 6c 65 2e 5b 25 64 5d } //01 00  It's Not PE File.[%d]
		$a_01_4 = {2e 63 6f 64 61 74 61 } //01 00  .codata
		$a_01_5 = {6a 66 6b 64 6a 76 65 75 6a 76 70 64 66 6a 67 64 33 34 3d 2d 33 32 31 } //00 00  jfkdjveujvpdfjgd34=-321
	condition:
		any of ($a_*)
 
}