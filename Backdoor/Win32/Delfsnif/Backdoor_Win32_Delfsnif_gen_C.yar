
rule Backdoor_Win32_Delfsnif_gen_C{
	meta:
		description = "Backdoor:Win32/Delfsnif.gen!C,SIGNATURE_TYPE_PEHSTR,23 00 21 00 0c 00 00 0a 00 "
		
	strings :
		$a_01_0 = {68 61 63 6b 65 64 20 62 79 20 4b 68 61 6c 65 64 } //0a 00  hacked by Khaled
		$a_01_1 = {4b 68 61 6c 6f 42 6f 74 20 76 20 31 2e 30 } //0a 00  KhaloBot v 1.0
		$a_01_2 = {2a 42 61 63 6b 64 6f 6f 72 20 25 73 20 62 79 20 4b 68 61 6c 65 64 20 28 63 29 20 32 30 30 35 2a } //01 00  *Backdoor %s by Khaled (c) 2005*
		$a_01_3 = {78 78 74 79 70 65 2e 63 70 70 } //01 00  xxtype.cpp
		$a_01_4 = {63 6c 69 65 6e 74 2e 65 78 65 } //01 00  client.exe
		$a_01_5 = {74 79 70 65 20 3d 2d 69 6e 66 6f 2d 3d 20 74 6f 20 67 65 74 20 76 69 63 74 69 6d 73 20 63 6f 6d 70 75 74 65 72 6e 61 6d 65 } //01 00  type =-info-= to get victims computername
		$a_01_6 = {74 79 70 65 20 3d 2d 6f 70 65 6e 63 64 2d 3d 20 74 6f 20 6f 70 65 6e 20 76 69 63 74 69 6d 73 20 63 64 20 72 6f 6d } //01 00  type =-opencd-= to open victims cd rom
		$a_01_7 = {74 79 70 65 20 3d 2d 62 6f 6d 62 2d 3d 20 74 6f 20 62 6f 6d 62 20 76 69 63 74 69 6d 20 77 69 74 68 20 6e 6f 74 65 70 61 64 } //01 00  type =-bomb-= to bomb victim with notepad
		$a_01_8 = {74 79 70 65 20 3d 2d 72 65 73 74 61 72 74 2d 3d 20 74 6f 20 72 65 73 74 61 72 74 20 76 69 63 74 69 6d 73 20 6d 61 63 68 69 6e 65 } //01 00  type =-restart-= to restart victims machine
		$a_01_9 = {74 79 70 65 20 3d 2d 75 72 6c 2d 3d 20 74 6f 20 73 74 61 72 74 20 77 77 77 2e 66 75 63 6b 2e 63 6f 6d } //01 00  type =-url-= to start www.fuck.com
		$a_01_10 = {74 79 70 65 20 3d 2d 64 6f 77 6e 2d 3d 20 74 6f 20 73 68 75 74 64 6f 77 6e 20 72 65 6d 6f 74 65 20 6d 61 63 68 69 6e 65 } //01 00  type =-down-= to shutdown remote machine
		$a_01_11 = {74 79 70 65 20 3d 2d 6c 61 62 65 6c 2d 3d 20 74 6f 20 72 65 6e 61 6d 65 20 6c 61 62 65 6c 20 74 6f 20 25 73 } //00 00  type =-label-= to rename label to %s
	condition:
		any of ($a_*)
 
}