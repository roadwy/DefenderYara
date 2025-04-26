
rule Backdoor_Win32_Leeson_B_dha{
	meta:
		description = "Backdoor:Win32/Leeson.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_00_0 = {ef 33 c0 8b c8 81 e1 07 00 00 80 } //2
		$a_01_1 = {5f 5f 56 49 45 57 53 54 41 54 45 } //1 __VIEWSTATE
		$a_01_2 = {5f 5f 45 56 45 4e 54 56 41 4c 49 44 41 54 49 4f 4e } //1 __EVENTVALIDATION
		$a_01_3 = {26 69 6d 61 67 65 43 6f 6e 3d } //1 &imageCon=
		$a_01_4 = {26 6d 65 73 73 61 67 65 43 6f 6e 3d } //1 &messageCon=
		$a_01_5 = {26 6d 65 73 73 61 67 65 49 64 3d } //1 &messageId=
		$a_00_6 = {25 00 73 00 5c 00 61 00 64 00 75 00 6c 00 74 00 2e 00 73 00 66 00 74 00 } //1 %s\adult.sft
	condition:
		((#a_00_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_00_6  & 1)*1) >=5
 
}