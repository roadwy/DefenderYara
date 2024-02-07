
rule Trojan_Win32_Midie_SIBH_MTB{
	meta:
		description = "Trojan:Win32/Midie.SIBH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {6a 73 61 6c 66 68 78 68 2e 64 6c 6c } //01 00  jsalfhxh.dll
		$a_03_1 = {33 c9 85 db 74 90 01 01 8a 04 39 90 02 0a 34 90 01 01 90 02 0a 04 90 01 01 34 90 01 01 88 04 39 41 3b cb 72 90 01 01 6a 00 57 6a 00 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Midie_SIBH_MTB_2{
	meta:
		description = "Trojan:Win32/Midie.SIBH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {64 63 6e 77 6e 71 73 67 2e 70 64 62 } //01 00  dcnwnqsg.pdb
		$a_03_1 = {6a 40 68 00 90 01 01 00 00 8b d8 53 6a 00 ff 15 90 01 04 6a 00 8b f8 8d 45 90 01 01 50 53 57 56 ff 15 90 01 04 33 c9 85 db 74 90 01 01 8a 04 39 90 02 20 34 90 01 01 90 02 20 34 90 01 01 90 02 20 34 90 01 01 88 04 39 41 3b cb 72 90 01 01 6a 00 6a 00 57 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Midie_SIBH_MTB_3{
	meta:
		description = "Trojan:Win32/Midie.SIBH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {5c 63 6f 6d 70 69 6c 69 6e 67 5c 66 6c 6f 63 6b 5c 61 64 6d 6f 6e 69 73 68 2e 6a 70 67 } //01 00  \compiling\flock\admonish.jpg
		$a_00_1 = {5c 70 72 6f 76 69 64 65 73 2e 65 78 65 } //01 00  \provides.exe
		$a_03_2 = {6a 40 57 8d 8d 90 01 04 51 ff d0 6a 00 68 80 00 00 00 6a 03 6a 00 6a 07 68 00 00 00 80 8d 85 90 01 04 50 ff 15 90 01 04 6a 00 8d 4d 90 01 01 51 57 8d 8d 90 1b 00 51 50 ff 15 90 01 04 b9 00 00 00 00 8a 84 0d 90 1b 00 81 f9 90 01 04 74 90 01 01 90 02 05 2c 14 34 84 90 02 08 2c e6 04 5f 34 2f 2c aa 90 02 08 88 84 0d 90 1b 00 83 c1 01 90 18 8a 84 0d 90 1b 00 81 f9 90 1b 07 90 18 b0 00 b9 00 00 00 00 8d 85 90 1b 00 ff d0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}