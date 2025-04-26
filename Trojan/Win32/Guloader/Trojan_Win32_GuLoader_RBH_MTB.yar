
rule Trojan_Win32_GuLoader_RBH_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RBH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {5c 65 78 75 6c 64 69 6e 67 5c 67 65 6e 72 65 62 65 73 74 65 6d 6d 65 6c 73 65 73 } //1 \exulding\genrebestemmelses
		$a_81_1 = {42 69 66 6c 6f 64 65 72 6e 65 39 30 2e 69 6e 69 } //1 Bifloderne90.ini
		$a_81_2 = {6d 61 72 6d 65 6c 61 64 65 6e 20 61 72 62 69 74 72 61 74 65 64 } //1 marmeladen arbitrated
		$a_81_3 = {69 63 68 74 68 79 69 73 6d 73 20 69 63 20 73 6c 76 74 6a } //1 ichthyisms ic slvtj
		$a_81_4 = {63 69 76 69 6c 6b 6f 6e 6f 6d 65 72 6e 65 20 62 69 64 69 72 65 63 74 69 6f 6e 61 6c } //1 civilkonomerne bidirectional
		$a_81_5 = {74 68 65 6c 6d 61 73 2e 65 78 65 } //1 thelmas.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}