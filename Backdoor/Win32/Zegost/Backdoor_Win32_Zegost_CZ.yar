
rule Backdoor_Win32_Zegost_CZ{
	meta:
		description = "Backdoor:Win32/Zegost.CZ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b 4d fc 80 04 11 da 03 ca 8b 4d fc 80 34 11 29 03 ca 42 3b d0 7c e9 } //1
		$a_00_1 = {66 75 63 6b 33 36 30 } //1 fuck360
		$a_02_2 = {42 6c 6f 63 6b 49 6e 70 75 74 [0-08] 57 69 6e 6c 6f 67 6f 6e } //1
		$a_00_3 = {53 59 53 54 45 4d 5c 47 72 6f 75 70 5c 47 72 6f 75 70 } //1 SYSTEM\Group\Group
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}