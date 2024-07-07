
rule PWS_Win32_OnLineGames_CH{
	meta:
		description = "PWS:Win32/OnLineGames.CH,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {68 6f 6f 6b 6f 66 66 00 68 6f 6f 6b 6f 6e 00 } //1
		$a_03_1 = {68 b8 0b 00 00 89 90 01 03 ff 15 90 01 02 40 00 8d 90 01 04 00 00 52 68 04 01 00 00 ff 15 90 01 02 40 00 90 02 20 51 6a 6a e8 0c fa ff ff 90 00 } //1
		$a_03_2 = {51 6a 6a e8 5b fc ff ff 83 c4 08 85 c0 5f 5e 5b 74 23 8d 94 90 01 04 00 52 6a 6b e8 90 01 04 83 c4 08 85 c0 74 0d 8d 90 01 03 50 e8 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}