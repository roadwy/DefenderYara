
rule Backdoor_Win32_Coolvidoor_G{
	meta:
		description = "Backdoor:Win32/Coolvidoor.G,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_01_0 = {41 43 54 49 4f 4e 20 48 41 53 20 53 54 41 52 54 45 44 20 41 54 3a } //1 ACTION HAS STARTED AT:
		$a_01_1 = {53 79 73 74 65 6d 20 6f 76 65 72 6c 6f 61 64 65 64 20 4e 6f 77 20 69 74 20 77 69 6c 6c 20 62 65 20 62 75 72 6e } //1 System overloaded Now it will be burn
		$a_01_2 = {4d 53 47 7c 44 72 69 76 65 20 6e 6f 74 20 61 63 63 65 73 73 69 62 6c 65 21 } //1 MSG|Drive not accessible!
		$a_01_3 = {2d 47 4f 43 48 41 54 7c } //1 -GOCHAT|
		$a_01_4 = {53 79 73 74 65 6d 20 48 61 6c 74 65 64 20 46 46 46 46 46 46 20 68 61 68 61 } //1 System Halted FFFFFF haha
		$a_01_5 = {5b 50 72 69 6e 74 20 53 63 72 65 65 6e 5d } //1 [Print Screen]
		$a_01_6 = {4a 61 6b 61 5f 4b 61 6d 75 5f 73 61 6c 65 6d } //1 Jaka_Kamu_salem
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=5
 
}