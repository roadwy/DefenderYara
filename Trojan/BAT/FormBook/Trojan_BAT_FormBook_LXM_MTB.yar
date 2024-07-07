
rule Trojan_BAT_FormBook_LXM_MTB{
	meta:
		description = "Trojan:BAT/FormBook.LXM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_03_0 = {03 08 03 6f 90 01 03 0a 5d 17 58 28 90 01 03 0a 28 90 01 03 0a 59 13 04 06 11 04 28 90 01 03 0a 28 90 01 03 0a 28 90 01 03 0a 0a 08 17 58 0c 08 09 31 c1 90 00 } //2
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_01_2 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_01_3 = {54 6f 53 74 72 69 6e 67 } //1 ToString
		$a_01_4 = {57 65 62 43 6c 69 65 6e 74 } //1 WebClient
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}