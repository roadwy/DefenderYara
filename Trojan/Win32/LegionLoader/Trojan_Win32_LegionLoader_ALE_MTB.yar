
rule Trojan_Win32_LegionLoader_ALE_MTB{
	meta:
		description = "Trojan:Win32/LegionLoader.ALE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {41 4f 49 41 4e 6d 76 69 67 73 6a 67 33 34 73 69 6f 68 } //1 AOIANmvigsjg34sioh
		$a_01_1 = {4c 61 70 71 70 64 6f 67 54 69 63 76 62 73 6f 68 } //1 LapqpdogTicvbsoh
		$a_01_2 = {61 73 6f 70 65 66 33 6a 67 68 69 6f 73 72 6a 68 34 39 68 65 6f } //1 asopef3jghiosrjh49heo
		$a_01_3 = {69 6f 64 72 67 6f 69 67 6a 77 34 6a 68 69 34 } //1 iodrgoigjw4jhi4
		$a_01_4 = {69 6f 73 67 6f 69 6a 73 34 6a 6a 67 73 72 69 6f 68 6a } //1 iosgoijs4jjgsriohj
		$a_01_5 = {6f 63 76 6f 69 62 6f 69 67 6a 33 34 39 38 30 67 73 65 72 6a 69 6f 68 } //1 ocvoiboigj34980gserjioh
		$a_01_6 = {78 63 69 6f 76 62 69 73 66 67 68 6a 77 67 68 77 } //1 xciovbisfghjwghw
		$a_01_7 = {78 69 6f 63 76 69 6f 62 73 6a 67 77 33 34 67 6a 69 68 } //1 xiocviobsjgw34gjih
		$a_01_8 = {7a 6f 76 69 65 6f 69 67 66 77 33 6a 39 38 72 6a 68 } //1 zovieoigfw3j98rjh
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}