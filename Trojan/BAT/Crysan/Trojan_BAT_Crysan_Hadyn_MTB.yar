
rule Trojan_BAT_Crysan_Hadyn_MTB{
	meta:
		description = "Trojan:BAT/Crysan.Hadyn!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 09 00 00 "
		
	strings :
		$a_81_0 = {52 65 76 65 72 73 65 } //2 Reverse
		$a_81_1 = {47 65 74 53 74 72 69 6e 67 } //2 GetString
		$a_81_2 = {47 65 74 54 79 70 65 } //2 GetType
		$a_81_3 = {58 55 78 49 6c 41 77 78 6c 50 44 67 62 62 74 } //2 XUxIlAwxlPDgbbt
		$a_81_4 = {54 6f 43 68 61 72 41 72 72 61 79 } //2 ToCharArray
		$a_81_5 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //2 DownloadData
		$a_81_6 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //2 InvokeMember
		$a_81_7 = {4f 53 4f 5a 76 44 73 66 78 7a 51 4e 6d 6b 65 51 64 43 6f 73 76 } //2 OSOZvDsfxzQNmkeQdCosv
		$a_80_8 = {6c 61 75 72 65 6e 74 70 72 6f 74 65 63 74 6f 72 2e 63 6f 6d } //laurentprotector.com  4
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2+(#a_81_3  & 1)*2+(#a_81_4  & 1)*2+(#a_81_5  & 1)*2+(#a_81_6  & 1)*2+(#a_81_7  & 1)*2+(#a_80_8  & 1)*4) >=20
 
}