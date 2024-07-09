
rule PWS_Win32_OnLineGames_IZ{
	meta:
		description = "PWS:Win32/OnLineGames.IZ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {85 db 74 0a 8a 06 32 c2 88 06 46 4b eb f2 } //1
		$a_03_1 = {83 ff 78 0f 82 ?? ?? ?? ?? 83 fe 64 0f 82 } //1
		$a_01_2 = {c6 04 3b e9 8b c6 2b c3 83 e8 05 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}