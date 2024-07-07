
rule PWS_Win32_OnLineGames_NH{
	meta:
		description = "PWS:Win32/OnLineGames.NH,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {83 3f 01 72 05 83 3f 2f 76 1e 83 3f 3a 72 05 83 3f 40 76 14 83 3f 5b 72 05 83 3f 60 76 0a 83 3f 7b 72 27 83 3f 7e 77 22 } //1
		$a_01_1 = {8b f0 85 ff 75 04 85 ed 74 5c 68 00 90 01 00 } //1
		$a_01_2 = {3f 61 63 74 3d } //1 ?act=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}