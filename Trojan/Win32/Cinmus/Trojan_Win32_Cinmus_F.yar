
rule Trojan_Win32_Cinmus_F{
	meta:
		description = "Trojan:Win32/Cinmus.F,SIGNATURE_TYPE_PEHSTR,09 00 09 00 07 00 00 "
		
	strings :
		$a_01_0 = {01 00 44 6f 53 53 53 65 74 75 70 2e 44 4c 4c 00 44 65 73 50 72 6f 00 44 6f 53 53 53 65 74 75 70 00 00 } //4
		$a_01_1 = {46 69 72 73 74 49 6e 73 74 61 6c 6c } //1 FirstInstall
		$a_01_2 = {76 65 72 69 6f 6e } //1 verion
		$a_01_3 = {64 64 64 64 2c 20 4d 4d 4d 4d 20 64 64 2c 20 79 79 79 79 } //1 dddd, MMMM dd, yyyy
		$a_01_4 = {47 65 74 4c 61 73 74 41 63 74 69 76 65 50 6f 70 75 70 } //1 GetLastActivePopup
		$a_01_5 = {3c 70 72 6f 67 72 61 6d 20 6e 61 6d 65 20 75 6e 6b 6e 6f 77 6e 3e } //1 <program name unknown>
		$a_01_6 = {43 72 65 61 74 65 4d 75 74 65 78 41 } //1 CreateMutexA
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=9
 
}