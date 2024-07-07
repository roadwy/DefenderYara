
rule Worm_Win32_Yimfoca_gen_B{
	meta:
		description = "Worm:Win32/Yimfoca.gen!B,SIGNATURE_TYPE_PEHSTR,06 00 06 00 07 00 00 "
		
	strings :
		$a_01_0 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 6e 76 73 76 63 33 32 2e 65 78 65 } //1 c:\windows\nvsvc32.exe
		$a_01_1 = {2a 3a 45 6e 61 62 6c 65 64 3a 4e 56 49 44 49 41 20 64 72 69 76 65 72 20 6d 6f 6e 69 74 6f 72 } //1 *:Enabled:NVIDIA driver monitor
		$a_01_2 = {6e 65 74 73 68 20 66 69 72 65 77 61 6c 6c 20 61 64 64 20 61 6c 6c 6f 77 65 64 70 72 6f 67 72 61 6d 20 31 2e 65 78 65 20 31 20 45 4e 41 42 4c 45 } //1 netsh firewall add allowedprogram 1.exe 1 ENABLE
		$a_01_3 = {65 78 70 6c 6f 72 65 72 2e 65 78 65 20 68 74 74 70 3a 2f 2f 62 72 6f 77 73 65 75 73 65 72 73 2e 6d 79 73 70 61 63 65 2e 63 6f 6d 2f 42 72 6f 77 73 65 2f 42 72 6f 77 73 65 2e 61 73 70 78 } //1 explorer.exe http://browseusers.myspace.com/Browse/Browse.aspx
		$a_01_4 = {6e 65 74 20 73 74 6f 70 20 77 75 61 75 73 65 72 76 } //1 net stop wuauserv
		$a_01_5 = {76 69 73 69 62 69 6c 69 74 79 3d 66 61 6c 73 65 26 70 6f 73 74 5f 66 6f 72 6d 5f 69 64 3d } //1 visibility=false&post_form_id=
		$a_01_6 = {50 69 6e 67 20 54 69 6d 65 6f 75 74 3f 20 28 25 64 2d 25 64 29 25 64 2f 25 64 } //1 Ping Timeout? (%d-%d)%d/%d
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=6
 
}