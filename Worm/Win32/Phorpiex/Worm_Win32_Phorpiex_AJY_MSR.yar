
rule Worm_Win32_Phorpiex_AJY_MSR{
	meta:
		description = "Worm:Win32/Phorpiex.AJY!MSR,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {68 74 74 70 3a 2f 2f 77 6f 72 6d 2e 77 73 2f } //1 http://worm.ws/
		$a_81_1 = {68 74 74 70 3a 2f 2f 73 65 75 75 66 68 65 68 66 75 65 75 67 68 65 6b 2e 77 73 2f } //1 http://seuufhehfueughek.ws/
		$a_81_2 = {68 74 74 70 3a 2f 2f 74 73 72 76 34 2e 77 73 2f } //1 http://tsrv4.ws/
		$a_01_3 = {25 00 73 00 5c 00 25 00 73 00 5c 00 44 00 72 00 69 00 76 00 65 00 4d 00 67 00 72 00 2e 00 65 00 78 00 65 00 } //1 %s\%s\DriveMgr.exe
		$a_01_4 = {2f 00 63 00 20 00 73 00 74 00 61 00 72 00 74 00 20 00 5f 00 5f 00 20 00 26 00 20 00 5f 00 5f 00 5c 00 44 00 72 00 69 00 76 00 65 00 4d 00 67 00 72 00 2e 00 65 00 78 00 65 00 20 00 26 00 20 00 65 00 78 00 69 00 74 00 } //1 /c start __ & __\DriveMgr.exe & exit
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}