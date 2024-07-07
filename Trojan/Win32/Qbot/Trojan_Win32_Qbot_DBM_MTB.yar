
rule Trojan_Win32_Qbot_DBM_MTB{
	meta:
		description = "Trojan:Win32/Qbot.DBM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 08 00 00 "
		
	strings :
		$a_81_0 = {79 69 71 44 7a 76 6f 4f 72 45 } //1 yiqDzvoOrE
		$a_81_1 = {62 6e 31 4c 6a 69 33 76 30 62 20 } //1 bn1Lji3v0b 
		$a_81_2 = {44 65 63 52 6c 7a 51 35 55 32 } //1 DecRlzQ5U2
		$a_81_3 = {67 54 7a 33 4a 6d 52 55 5a 31 36 63 70 } //1 gTz3JmRUZ16cp
		$a_81_4 = {52 6a 74 4c 37 66 33 6c 69 47 38 57 6d } //1 RjtL7f3liG8Wm
		$a_81_5 = {32 63 77 75 58 67 41 4a 76 45 64 77 77 62 31 51 } //1 2cwuXgAJvEdwwb1Q
		$a_81_6 = {76 63 41 4c 6e 68 33 72 43 31 6d 63 38 4f 4d 33 69 55 34 } //1 vcALnh3rC1mc8OM3iU4
		$a_81_7 = {65 45 59 79 53 4b 51 37 39 6c 37 31 6c 54 45 } //1 eEYySKQ79l71lTE
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=1
 
}