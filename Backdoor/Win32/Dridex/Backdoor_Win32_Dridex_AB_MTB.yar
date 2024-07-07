
rule Backdoor_Win32_Dridex_AB_MTB{
	meta:
		description = "Backdoor:Win32/Dridex.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {72 70 5a 6d 51 32 35 56 6d 36 } //rpZmQ25Vm6  3
		$a_80_1 = {6f 4b 47 33 55 6b 5a 67 } //oKG3UkZg  3
		$a_80_2 = {32 48 53 71 74 78 39 55 69 68 } //2HSqtx9Uih  3
		$a_80_3 = {43 4c 49 50 46 4f 52 4d 41 54 5f 55 73 65 72 4d 61 72 73 68 61 6c } //CLIPFORMAT_UserMarshal  3
		$a_80_4 = {43 72 65 61 74 65 50 72 6f 70 65 72 74 79 53 68 65 65 74 50 61 67 65 57 } //CreatePropertySheetPageW  3
		$a_80_5 = {47 65 74 54 65 6d 70 46 69 6c 65 4e 61 6d 65 41 } //GetTempFileNameA  3
		$a_80_6 = {53 48 47 65 74 55 6e 72 65 61 64 4d 61 69 6c 43 6f 75 6e 74 57 } //SHGetUnreadMailCountW  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}