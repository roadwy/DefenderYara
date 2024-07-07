
rule Backdoor_Win32_Koceg_gen_E{
	meta:
		description = "Backdoor:Win32/Koceg.gen!E,SIGNATURE_TYPE_PEHSTR_EXT,33 00 33 00 08 00 00 "
		
	strings :
		$a_00_0 = {72 6b 20 25 64 20 25 64 } //10 rk %d %d
		$a_00_1 = {66 74 70 3a 2f 2f 25 73 3a 25 73 40 25 73 } //10 ftp://%s:%s@%s
		$a_00_2 = {53 65 53 68 75 74 64 6f 77 6e 50 72 69 76 69 6c 65 67 65 } //10 SeShutdownPrivilege
		$a_00_3 = {56 69 72 75 73 } //10 Virus
		$a_00_4 = {45 78 70 6c 6f 69 74 } //10 Exploit
		$a_02_5 = {8b 45 08 03 45 fc 0f be 00 33 45 90 01 01 8b 4d 08 03 4d fc 88 01 eb 90 00 } //1
		$a_02_6 = {8b 45 08 03 45 fc 0f be 00 35 90 01 04 8b 4d 08 03 4d fc 88 01 eb 90 00 } //1
		$a_02_7 = {8b 45 08 03 45 90 01 01 0f be 00 0f be 4d fc 33 90 01 01 8b 4d f8 03 4d f4 88 41 fe eb 90 00 } //1
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_00_4  & 1)*10+(#a_02_5  & 1)*1+(#a_02_6  & 1)*1+(#a_02_7  & 1)*1) >=51
 
}