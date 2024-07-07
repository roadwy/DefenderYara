
rule PWS_Win32_OnLineGames_GM{
	meta:
		description = "PWS:Win32/OnLineGames.GM,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {52 55 4e 49 54 } //1 RUNIT
		$a_01_1 = {5c 63 6f 6d 72 65 73 72 65 61 6c 2e 64 6c 6c } //1 \comresreal.dll
		$a_01_2 = {5c 6d 79 5f 73 66 63 5f 6f 73 2e 64 6c 6c } //1 \my_sfc_os.dll
		$a_01_3 = {68 65 64 67 65 70 69 67 2e 64 61 74 } //2 hedgepig.dat
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2) >=4
 
}
rule PWS_Win32_OnLineGames_GM_2{
	meta:
		description = "PWS:Win32/OnLineGames.GM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {8a 14 37 8a 04 28 32 c2 74 04 88 06 eb 02 88 16 46 49 75 dd } //1
		$a_01_1 = {8a 0c 07 32 0c 1a 40 4d 88 48 ff 75 e4 } //1
		$a_00_2 = {68 65 64 67 65 70 69 67 2e 64 61 74 00 } //1
		$a_00_3 = {54 65 73 74 44 6c 6c 2e 64 6c 6c 00 43 4f 4d 52 65 73 4d 6f 64 75 6c 65 49 6e 73 74 61 6e 63 65 00 53 65 74 49 6e 73 65 72 74 48 6f 6f 6b 00 55 6e 49 6e 73 65 72 74 48 6f 6f 6b 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}