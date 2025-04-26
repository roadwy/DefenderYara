
rule PWS_Win32_OnLineGames_LK{
	meta:
		description = "PWS:Win32/OnLineGames.LK,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 03 00 00 "
		
	strings :
		$a_01_0 = {05 00 00 00 57 49 4e 4e 54 00 00 00 ff ff ff ff 06 00 00 00 53 68 61 6e 64 61 00 00 ff ff ff ff } //5
		$a_01_1 = {53 79 73 74 65 6d 20 56 6f 6c 75 6d 65 20 49 6e 66 6f 72 6d 61 74 69 6f 6e } //1 System Volume Information
		$a_01_2 = {00 43 4f 4d 53 50 45 43 00 2f 63 20 64 65 6c 20 00 20 3e 20 6e 75 6c 00 00 4f 70 65 6e 00 } //3
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*3) >=9
 
}