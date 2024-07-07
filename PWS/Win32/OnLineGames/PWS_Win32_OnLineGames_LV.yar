
rule PWS_Win32_OnLineGames_LV{
	meta:
		description = "PWS:Win32/OnLineGames.LV,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {2f 63 78 70 69 64 2f 73 75 62 6d 69 74 2e 70 68 70 3f 53 65 73 73 69 6f 6e 49 44 3d } //1 /cxpid/submit.php?SessionID=
		$a_03_1 = {8b d0 8a 83 90 01 04 32 d0 8d 45 f4 e8 90 01 04 8b 55 f4 8b c7 e8 90 01 04 43 81 e3 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}