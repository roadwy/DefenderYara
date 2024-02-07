
rule Trojan_Win32_Midie_SIBK_MTB{
	meta:
		description = "Trojan:Win32/Midie.SIBK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {5c 62 72 65 61 6b 74 68 72 6f 75 67 68 5c 69 6e 74 65 67 72 61 6c 2e 64 6c 6c } //01 00  \breakthrough\integral.dll
		$a_00_1 = {5c 64 69 73 61 67 72 65 65 6d 65 6e 74 73 2e 61 75 } //01 00  \disagreements.au
		$a_03_2 = {68 80 00 00 00 6a 03 56 6a 07 68 00 00 00 80 50 ff 15 90 01 04 56 8d 4d 90 01 01 be 90 01 04 51 56 8d 8d 90 01 04 51 50 ff 15 90 01 04 b9 00 00 00 00 8a 84 0d 90 1b 03 81 f9 90 1b 02 74 90 01 01 90 02 08 2c 90 01 01 90 02 08 34 90 01 01 90 02 15 2c 90 01 01 90 02 05 04 90 01 01 88 84 0d 90 1b 03 83 c1 01 90 18 8a 84 0d 90 1b 03 81 f9 90 1b 02 90 18 b0 00 b9 00 00 00 00 68 90 01 01 90 01 03 68 90 01 01 90 1b 16 ff 15 90 01 04 50 ff 15 90 01 04 8d 4d 90 01 01 51 6a 40 56 8d 8d 90 1b 03 51 ff d0 8d 85 90 1b 03 ff d0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}