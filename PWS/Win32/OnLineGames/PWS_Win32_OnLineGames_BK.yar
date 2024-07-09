
rule PWS_Win32_OnLineGames_BK{
	meta:
		description = "PWS:Win32/OnLineGames.BK,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {68 00 00 00 80 ff ?? ?? ff 15 ?? ?? ?? ?? 8b f8 83 ff ff 74 ?? 90 90 90 90 90 90 90 90 [0-08] 8d ?? ?? 56 50 ff ?? ?? ff ?? ?? 57 ff 15 } //1
		$a_03_1 = {68 e8 03 00 00 ff 15 ?? ?? ?? ?? ff 05 ?? ?? ?? ?? eb } //1
		$a_02_2 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c [0-10] 2e 69 6e 69 } //1
		$a_02_3 = {68 74 74 70 3a 2f 2f [0-20] 73 3f 25 73 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1) >=4
 
}