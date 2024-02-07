
rule BrowserModifier_Win32_SearchExtender{
	meta:
		description = "BrowserModifier:Win32/SearchExtender,SIGNATURE_TYPE_PEHSTR_EXT,1d 00 18 00 07 00 00 02 00 "
		
	strings :
		$a_00_0 = {33 db 83 c4 10 39 1d 30 41 00 10 0f 85 93 01 00 00 39 1d 34 41 00 10 0f 85 87 01 00 00 57 53 8d 8d a0 f6 ff ff e8 13 ff ff ff 68 19 00 02 00 8d 45 b4 50 bf 01 00 00 80 57 8d 8d a0 f6 ff ff e8 a0 fe ff ff 84 c0 74 3b 8d 45 f4 50 8d 8d a0 f6 ff ff e8 0e ff ff ff 84 c0 74 28 83 bd ac fe ff ff 03 75 1f 83 bd a8 fe ff ff 08 75 16 8b 85 a4 fa ff ff a3 30 41 00 10 8b 85 a8 fa ff } //01 00 
		$a_00_1 = {59 68 06 00 02 00 8d 45 d0 50 68 02 00 00 80 8d 8d c0 f6 ff ff e8 f3 fc ff ff 84 c0 74 5f 8d 85 d0 fe ff ff 68 } //03 00 
		$a_01_2 = {67 2d fa 54 25 d1 aa ad ae cd ae e2 f6 f8 dd c6 6e 5c 24 6d 67 70 23 ee cd 17 f0 ab 25 3b f6 8f 9b 26 b0 cf 7b 80 c5 b3 f9 63 3f d0 ee 5d 00 00 3d 5f 4c 3d 00 00 00 00 } //05 00 
		$a_00_3 = {5b c9 c3 55 8b ec 81 ec 40 09 00 00 6a 00 8d 8d c0 f6 ff ff e8 75 fd ff ff 8d 45 d0 68 } //07 00 
		$a_01_4 = {10 49 00 45 00 54 00 65 00 78 00 74 00 00 00 00 00 } //07 00 
		$a_01_5 = {73 65 61 72 63 68 2d 70 69 6e 28 } //07 00  search-pin(
		$a_01_6 = {29 2e 64 6c 6c 00 44 6c 6c 49 6e 73 74 61 6c 6c 00 } //00 00 
	condition:
		any of ($a_*)
 
}