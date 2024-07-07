
rule Backdoor_Win32_Nethief_Y{
	meta:
		description = "Backdoor:Win32/Nethief.Y,SIGNATURE_TYPE_PEHSTR,03 00 03 00 09 00 00 "
		
	strings :
		$a_01_0 = {6e 65 74 68 69 65 66 2d 63 61 6c 6c 62 6f 61 72 64 2f 4e 65 74 } //1 nethief-callboard/Net
		$a_01_1 = {4e 65 74 68 69 65 66 20 69 73 20 74 65 73 74 69 6e 67 2e 2e 2e 21 } //1 Nethief is testing...!
		$a_01_2 = {4e 65 74 68 69 65 66 5f 53 65 72 76 65 72 } //1 Nethief_Server
		$a_01_3 = {4e 65 74 68 69 65 66 5f 43 6f 6e 6e 65 63 74 2e } //1 Nethief_Connect.
		$a_01_4 = {4e 65 74 68 69 65 66 5f 4e 6f 74 69 66 79 2e } //1 Nethief_Notify.
		$a_01_5 = {68 69 65 66 5f 53 65 72 76 65 72 20 2d } //1 hief_Server -
		$a_01_6 = {64 65 6c 20 4e 65 74 68 69 65 66 } //1 del Nethief
		$a_01_7 = {74 68 69 65 66 5f 43 61 6c 6c 62 6f 61 72 64 2e 64 61 74 } //1 thief_Callboard.dat
		$a_01_8 = {74 68 69 65 66 5f 56 65 72 73 69 6f 6e 2e 64 61 74 } //1 thief_Version.dat
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=3
 
}