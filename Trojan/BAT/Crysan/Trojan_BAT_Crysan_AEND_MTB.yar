
rule Trojan_BAT_Crysan_AEND_MTB{
	meta:
		description = "Trojan:BAT/Crysan.AEND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_80_1 = {57 65 62 43 6c 69 65 6e 74 } //WebClient  1
		$a_01_2 = {6c 00 61 00 75 00 72 00 65 00 6e 00 74 00 70 00 72 00 6f 00 74 00 65 00 63 00 74 00 6f 00 72 00 2e 00 63 00 6f 00 6d 00 } //1 laurentprotector.com
		$a_81_3 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_81_4 = {47 65 74 54 79 70 65 } //1 GetType
		$a_01_5 = {44 00 69 00 66 00 66 00 4c 00 65 00 76 00 65 00 6c 00 2e 00 42 00 7a 00 73 00 74 00 65 00 75 00 4d 00 79 00 42 00 44 00 5a 00 65 00 50 00 57 00 4d 00 } //1 DiffLevel.BzsteuMyBDZePWM
		$a_01_6 = {51 00 76 00 72 00 54 00 4f 00 5a 00 6d 00 41 00 6b 00 4e 00 4e 00 58 00 6f 00 6d 00 77 00 } //1 QvrTOZmAkNNXomw
	condition:
		((#a_81_0  & 1)*1+(#a_80_1  & 1)*1+(#a_01_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}