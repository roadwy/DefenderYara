
rule PWS_Win32_OnLineGames_KX{
	meta:
		description = "PWS:Win32/OnLineGames.KX,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {25 73 3f 61 31 3d 25 64 26 61 33 3d 25 73 26 61 34 3d 25 73 26 61 36 3d 25 73 00 } //1
		$a_01_1 = {25 73 64 66 2e 69 6e 69 00 } //1
		$a_01_2 = {32 0c 02 88 08 40 ff 4d 08 89 45 18 75 ae } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}