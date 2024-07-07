
rule Trojan_BAT_FormBook_EYL_MTB{
	meta:
		description = "Trojan:BAT/FormBook.EYL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {4e 00 63 00 6a 00 68 00 64 00 73 00 66 00 75 00 } //1 Ncjhdsfu
		$a_01_1 = {70 00 6a 00 64 00 66 00 73 00 67 00 79 00 75 00 66 00 69 00 75 00 6a 00 67 00 } //1 pjdfsgyufiujg
		$a_01_2 = {78 00 63 00 6b 00 6a 00 76 00 62 00 76 00 69 00 67 00 66 00 6f 00 72 00 67 00 } //1 xckjvbvigforg
		$a_01_3 = {7a 00 4c 00 7a 00 6f 00 7a 00 61 00 7a 00 64 00 7a 00 } //1 zLzozazdz
		$a_01_4 = {49 00 6e 00 76 00 6f 00 6b 00 65 00 4d 00 65 00 6d 00 62 00 65 00 72 00 } //1 InvokeMember
		$a_01_5 = {44 00 4d 00 44 00 65 00 44 00 74 00 44 00 68 00 44 00 6f 00 44 00 64 00 44 00 30 00 44 00 } //1 DMDeDtDhDoDdD0D
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}