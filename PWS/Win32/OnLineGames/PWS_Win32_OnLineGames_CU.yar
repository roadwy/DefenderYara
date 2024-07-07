
rule PWS_Win32_OnLineGames_CU{
	meta:
		description = "PWS:Win32/OnLineGames.CU,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {26 65 61 72 74 68 77 6f 72 6d 32 3d 00 00 00 00 26 74 75 72 74 6c 65 32 3d } //1
		$a_03_1 = {81 ff 2c 01 00 00 77 90 01 01 68 90 01 02 00 10 55 e8 90 01 02 ff ff 8b f0 bb 90 01 02 00 10 56 53 55 e8 90 01 02 ff ff 2b c6 83 c6 0d 83 e8 0d 50 56 90 00 } //1
		$a_03_2 = {85 c9 7c 26 85 c0 7c 22 85 ff 74 1e 83 c1 05 51 68 90 01 04 55 e8 90 01 02 ff ff 8b 4c 90 01 02 2b c1 83 e8 0a 83 c1 0a 50 eb 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}