
rule Trojan_BAT_FormBook_NH_MTB{
	meta:
		description = "Trojan:BAT/FormBook.NH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_03_0 = {59 d2 9c 06 17 58 0a 00 06 7e 90 01 01 00 00 04 8e 69 fe 04 0b 07 90 00 } //7
		$a_81_1 = {54 78 74 50 61 73 73 77 6f 72 64 } //1 TxtPassword
		$a_81_2 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_81_3 = {45 6c 72 6d 61 69 6e 5c 6f 62 6a 5c 44 65 62 75 67 5c 45 6c 72 6d 61 69 6e 2e 70 64 62 } //1 Elrmain\obj\Debug\Elrmain.pdb
	condition:
		((#a_03_0  & 1)*7+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=10
 
}