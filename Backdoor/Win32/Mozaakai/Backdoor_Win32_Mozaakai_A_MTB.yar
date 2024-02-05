
rule Backdoor_Win32_Mozaakai_A_MTB{
	meta:
		description = "Backdoor:Win32/Mozaakai.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 09 00 00 01 00 "
		
	strings :
		$a_80_0 = {77 6f 72 6b 72 65 70 61 69 72 2e 62 61 7a 61 72 } //workrepair.bazar  01 00 
		$a_80_1 = {72 65 61 6c 66 69 73 68 2e 62 61 7a 61 72 } //realfish.bazar  01 00 
		$a_80_2 = {65 76 65 6e 74 6d 6f 75 6c 74 2e 62 61 7a 61 72 } //eventmoult.bazar  01 00 
		$a_80_3 = {79 6f 75 6e 69 6b 61 2d 68 61 79 64 65 2e 62 61 7a 61 72 } //younika-hayde.bazar  05 00 
		$a_80_4 = {53 6c 65 65 70 20 25 75 20 6d 73 65 63 73 } //Sleep %u msecs  05 00 
		$a_80_5 = {52 75 6e 20 50 6f 77 65 72 53 68 65 6c 6c 20 73 63 72 69 70 74 20 77 69 74 68 6f 75 74 20 61 20 66 69 6c 65 } //Run PowerShell script without a file  05 00 
		$a_80_6 = {6f 73 5b 31 5d 3d 26 6f 73 5b 32 5d 3d 26 6f 73 5b 33 5d 3d } //os[1]=&os[2]=&os[3]=  05 00 
		$a_80_7 = {47 65 74 74 69 6e 67 20 61 6e 74 69 76 69 72 75 73 65 73 20 76 65 72 73 69 6f 6e 73 } //Getting antiviruses versions  05 00 
		$a_80_8 = {6e 65 74 20 6c 6f 63 61 6c 67 72 6f 75 70 20 22 61 64 6d 69 6e 69 73 74 72 61 74 6f 72 } //net localgroup "administrator  00 00 
	condition:
		any of ($a_*)
 
}