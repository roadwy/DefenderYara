
rule TrojanClicker_Win32_Baffec_A{
	meta:
		description = "TrojanClicker:Win32/Baffec.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2d 00 2d 00 73 00 69 00 6c 00 65 00 6e 00 74 00 } //1 --silent
		$a_00_1 = {2f 00 63 00 6c 00 69 00 63 00 6b 00 2e 00 70 00 68 00 70 00 3f 00 76 00 65 00 72 00 3d 00 25 00 73 00 26 00 74 00 79 00 70 00 65 00 3d 00 25 00 73 00 } //1 /click.php?ver=%s&type=%s
		$a_00_2 = {54 69 6d 65 72 52 65 70 6f 72 74 54 69 6d 65 72 } //1 TimerReportTimer
		$a_01_3 = {4d 00 45 00 44 00 49 00 41 00 5f 00 53 00 45 00 41 00 52 00 43 00 48 00 5f 00 43 00 4c 00 4f 00 53 00 45 00 5f 00 4d 00 45 00 53 00 53 00 41 00 47 00 45 00 } //1 MEDIA_SEARCH_CLOSE_MESSAGE
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}