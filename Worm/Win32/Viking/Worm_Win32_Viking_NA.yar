
rule Worm_Win32_Viking_NA{
	meta:
		description = "Worm:Win32/Viking.NA,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 03 00 "
		
	strings :
		$a_03_0 = {2e 62 73 00 8b 85 90 01 02 ff ff 89 85 90 01 02 ff ff 8b 85 90 01 02 ff ff ff 70 38 a1 90 01 04 05 90 01 04 50 e8 90 01 02 ff ff 90 00 } //01 00 
		$a_02_1 = {00 65 78 65 00 90 02 10 68 74 6d 90 02 10 68 74 6d 6c 90 02 10 61 73 70 90 02 10 61 73 70 78 90 02 10 72 61 72 90 00 } //01 00 
		$a_00_2 = {47 45 54 20 25 73 3f 6e 61 6d 65 3d 25 73 20 48 54 54 50 2f 31 2e 31 } //01 00  GET %s?name=%s HTTP/1.1
		$a_02_3 = {5b 61 75 74 6f 72 75 6e 5d 0d 0a 4f 50 45 4e 3d 25 73 5c 25 73 0d 0a 73 68 65 6c 6c 5c 6f 70 65 6e 3d 90 02 12 73 68 65 6c 6c 5c 6f 70 65 6e 5c 43 6f 6d 6d 61 6e 64 3d 25 73 5c 25 73 20 25 73 0d 0a 73 68 65 6c 6c 5c 6f 70 65 6e 5c 44 65 66 61 75 6c 74 3d 90 00 } //01 00 
		$a_01_4 = {4d 53 4e 20 47 61 6d 69 6e 67 20 5a 6f 6e 65 } //00 00  MSN Gaming Zone
	condition:
		any of ($a_*)
 
}