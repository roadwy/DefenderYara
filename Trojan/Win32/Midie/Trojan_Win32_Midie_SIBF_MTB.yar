
rule Trojan_Win32_Midie_SIBF_MTB{
	meta:
		description = "Trojan:Win32/Midie.SIBF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {5c 74 72 61 70 70 65 64 2e 70 64 66 } //01 00  \trapped.pdf
		$a_00_1 = {5c 68 6f 74 64 6f 67 2e 64 6c 6c } //01 00  \hotdog.dll
		$a_03_2 = {6a 40 57 8d 8d 90 01 04 51 ff d0 6a 00 68 80 00 00 00 6a 03 6a 00 6a 07 68 00 00 00 80 8d 85 90 01 04 50 ff 15 90 01 04 6a 00 8d 4d 90 01 01 51 57 8d 8d 90 1b 00 51 50 ff 15 90 01 04 b9 00 00 00 00 8a 84 0d 90 1b 00 81 f9 90 01 04 74 90 01 01 90 02 05 04 2d 34 24 90 02 08 2c 77 90 02 08 04 ea 90 02 05 34 65 88 84 0d 90 1b 00 83 c1 01 90 18 8a 84 0d 90 1b 00 81 f9 90 1b 07 90 18 b0 00 b9 00 00 00 00 8d 85 90 1b 00 ff d0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}