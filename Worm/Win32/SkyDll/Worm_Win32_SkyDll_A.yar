
rule Worm_Win32_SkyDll_A{
	meta:
		description = "Worm:Win32/SkyDll.A,SIGNATURE_TYPE_PEHSTR,06 00 06 00 0c 00 00 03 00 "
		
	strings :
		$a_01_0 = {6c 6f 6c 21 21 21 20 7b 66 75 6c 6c 6e 61 6d 65 7d 20 76 69 64 65 6f 3a 20 68 74 74 70 3a 2f 2f } //02 00  lol!!! {fullname} video: http://
		$a_01_1 = {2f 73 66 63 66 67 2e 74 78 74 } //01 00  /sfcfg.txt
		$a_01_2 = {73 6b 79 70 65 5f 72 65 73 74 61 72 74 5f 6d 69 6e 73 } //01 00  skype_restart_mins
		$a_01_3 = {6f 6c 64 5f 66 72 69 65 6e 64 5f 68 6f 75 72 73 } //01 00  old_friend_hours
		$a_01_4 = {64 65 6c 5f 6d 73 67 73 5f 6c 69 6d 69 74 } //01 00  del_msgs_limit
		$a_01_5 = {73 65 6e 64 5f 73 74 72 61 74 65 67 79 } //01 00  send_strategy
		$a_01_6 = {6d 61 78 5f 6c 6f 63 5f 6d 73 67 73 } //01 00  max_loc_msgs
		$a_01_7 = {73 6f 6d 65 73 6b 79 70 65 2e 63 6f 6d } //01 00  someskype.com
		$a_01_8 = {73 6f 6d 65 73 6b 79 70 65 2e 6e 65 74 } //01 00  someskype.net
		$a_01_9 = {6c 65 74 73 6b 79 70 65 2e 6e 65 74 } //01 00  letskype.net
		$a_01_10 = {69 72 6f 6e 73 6b 79 70 65 2e 6e 65 74 } //01 00  ironskype.net
		$a_01_11 = {64 65 65 70 73 6b 79 70 65 2e 6e 65 74 } //00 00  deepskype.net
		$a_01_12 = {00 67 } //16 00  最
	condition:
		any of ($a_*)
 
}