
rule PWS_Win32_OnLineGames_KM{
	meta:
		description = "PWS:Win32/OnLineGames.KM,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6a 00 6a 6c 68 cc 00 00 00 50 ff d6 } //1
		$a_01_1 = {6a 14 c1 fe 08 83 e6 01 ff 15 } //1
		$a_00_2 = {00 54 57 49 4e 43 4f 4e 54 52 4f 4c 00 } //1
		$a_00_3 = {00 44 4e 46 63 68 69 6e 61 2e 65 78 65 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}