
rule Trojan_Win32_Midie_SIBN_MTB{
	meta:
		description = "Trojan:Win32/Midie.SIBN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {5c 62 72 65 61 6b 74 68 72 6f 75 67 68 2e 70 64 66 } //01 00  \breakthrough.pdf
		$a_00_1 = {5c 63 6c 61 73 73 69 63 61 6c 2e 6c 6e 6b } //01 00  \classical.lnk
		$a_03_2 = {6a 40 57 8d 8d 90 01 04 51 ff d0 6a 00 68 80 00 00 00 6a 03 6a 00 6a 07 68 00 00 00 80 8d 85 90 01 04 50 ff 15 90 01 04 6a 00 8d 4d 90 01 01 51 57 8d 8d 90 1b 00 51 50 ff 15 90 01 04 b9 00 00 00 00 8a 84 0d 90 1b 00 81 f9 90 01 04 74 90 01 01 2c 90 01 01 90 02 08 34 90 01 01 90 02 06 04 90 01 01 90 02 08 2c 90 01 01 88 84 0d 90 1b 00 83 c1 01 90 18 8a 84 0d 90 1b 00 81 f9 90 1b 07 90 18 b0 00 b9 00 00 00 00 8d 85 90 1b 00 ff d0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}