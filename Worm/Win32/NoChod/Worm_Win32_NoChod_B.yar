
rule Worm_Win32_NoChod_B{
	meta:
		description = "Worm:Win32/NoChod.B,SIGNATURE_TYPE_PEHSTR_EXT,5a 00 5a 00 09 00 00 "
		
	strings :
		$a_80_0 = {43 68 6f 64 65 42 6f 74 20 4e 61 74 68 61 6e } //ChodeBot Nathan  10
		$a_80_1 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 4d 65 73 73 65 6e 67 65 72 5c 6d 73 6d 73 67 73 2e 65 78 65 5c 33 } //C:\Program Files\Messenger\msmsgs.exe\3  10
		$a_80_2 = {48 54 54 50 20 46 6c 6f 6f 64 69 6e 67 3a } //HTTP Flooding:  10
		$a_80_3 = {55 44 50 20 46 6c 6f 6f 64 69 6e 67 3a } //UDP Flooding:  10
		$a_80_4 = {50 69 6e 67 20 46 6c 6f 6f 64 69 6e 67 3a } //Ping Flooding:  10
		$a_80_5 = {54 43 50 20 46 6c 6f 6f 64 69 6e 67 3a } //TCP Flooding:  10
		$a_80_6 = {6e 65 74 73 68 2e 65 78 65 20 66 69 72 65 77 61 6c 6c 20 73 65 74 20 6f 70 6d 6f 64 65 20 6d 6f 64 65 3d 64 69 73 61 62 6c 65 20 70 72 6f 66 69 6c 65 3d 61 6c 6c } //netsh.exe firewall set opmode mode=disable profile=all  10
		$a_00_7 = {5b 00 53 00 50 00 52 00 45 00 41 00 44 00 4d 00 53 00 4e 00 5d 00 3a 00 20 00 53 00 74 00 61 00 72 00 74 00 65 00 64 00 20 00 4d 00 53 00 4e 00 20 00 73 00 70 00 72 00 65 00 61 00 64 00 65 00 72 00 } //10 [SPREADMSN]: Started MSN spreader
		$a_00_8 = {5b 00 4d 00 53 00 4e 00 53 00 50 00 52 00 45 00 41 00 44 00 5d 00 3a 00 20 00 53 00 74 00 6f 00 70 00 70 00 65 00 64 00 20 00 4d 00 53 00 4e 00 20 00 73 00 70 00 72 00 65 00 61 00 64 00 65 00 72 00 } //10 [MSNSPREAD]: Stopped MSN spreader
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*10+(#a_80_2  & 1)*10+(#a_80_3  & 1)*10+(#a_80_4  & 1)*10+(#a_80_5  & 1)*10+(#a_80_6  & 1)*10+(#a_00_7  & 1)*10+(#a_00_8  & 1)*10) >=90
 
}