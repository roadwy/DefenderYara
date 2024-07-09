
rule PWS_Win32_OnLineGames_DG{
	meta:
		description = "PWS:Win32/OnLineGames.DG,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {6d 64 6d 33 36 35 2e 65 78 65 00 } //1
		$a_00_1 = {46 69 72 73 74 52 75 6e 00 } //1
		$a_00_2 = {68 61 6c 6c 5f 6d 64 6d 5f 64 6c 6c 00 } //1
		$a_03_3 = {6a 00 6a 42 68 ?? ?? 40 00 6a 00 6a 00 e8 ?? ?? ff ff 33 c0 5a 59 59 64 89 10 } //1
		$a_03_4 = {50 6a 02 e8 ?? ?? ff ff a3 ?? ?? 40 00 6a 00 a1 ?? ?? 40 00 50 b8 ?? ?? 40 00 50 6a 07 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}