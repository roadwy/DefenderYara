
rule Backdoor_Win32_Prorat_AM{
	meta:
		description = "Backdoor:Win32/Prorat.AM,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 0d 00 00 "
		
	strings :
		$a_01_0 = {33 33 31 20 50 61 73 73 77 6f 72 64 20 72 65 71 75 69 72 65 64 20 66 6f 72 20 25 73 2e } //1 331 Password required for %s.
		$a_01_1 = {54 43 75 73 74 6f 6d 53 6d 74 70 43 6c 69 65 6e 74 } //1 TCustomSmtpClient
		$a_01_2 = {4d 41 49 4c 20 46 52 4f 4d 3a 3c } //1 MAIL FROM:<
		$a_00_3 = {50 72 6f 52 61 74 20 2d 20 54 72 6f 6a 61 6e 20 48 6f 72 73 65 20 2d 20 43 6f 64 65 64 20 62 79 } //3 ProRat - Trojan Horse - Coded by
		$a_01_4 = {50 72 6f 52 61 74 40 59 61 68 6f 6f 2e 43 6f 6d } //3 ProRat@Yahoo.Com
		$a_01_5 = {44 65 64 65 63 74 65 64 20 62 75 72 75 74 65 20 66 6f 72 63 65 20 61 74 61 63 6b } //3 Dedected burute force atack
		$a_01_6 = {5f 52 65 61 64 43 64 4b 65 79 73 } //1 _ReadCdKeys
		$a_01_7 = {49 43 51 5f 55 49 4e } //1 ICQ_UIN
		$a_01_8 = {2f 2f 2f 20 55 52 4c 20 48 49 53 54 4f 52 59 } //1 /// URL HISTORY
		$a_01_9 = {43 6f 6d 6d 61 6e 64 3d 54 6f 67 67 6c 65 44 65 73 6b 74 6f 70 } //1 Command=ToggleDesktop
		$a_01_10 = {55 73 65 72 20 63 6c 69 63 6b 65 64 3a 20 52 45 54 52 59 } //1 User clicked: RETRY
		$a_01_11 = {53 65 74 20 63 64 61 75 64 69 6f 20 64 6f 6f 72 } //1 Set cdaudio door
		$a_01_12 = {56 69 63 74 69 6d 20 6e 61 6d 65 } //1 Victim name
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*3+(#a_01_4  & 1)*3+(#a_01_5  & 1)*3+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1) >=8
 
}
rule Backdoor_Win32_Prorat_AM_2{
	meta:
		description = "Backdoor:Win32/Prorat.AM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {54 72 6f 6a 61 6e 20 48 6f 72 73 65 20 2d 20 43 6f 64 65 64 20 62 79 } //1 Trojan Horse - Coded by
		$a_01_1 = {2e 64 6c 6c 00 48 6f 6f 6b 50 72 6f 63 00 49 6e 73 74 61 6c 6c 48 6f 6f 6b 00 52 65 6d 6f 76 65 } //1 搮汬䠀潯偫潲c湉瑳污䡬潯k敒潭敶
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}