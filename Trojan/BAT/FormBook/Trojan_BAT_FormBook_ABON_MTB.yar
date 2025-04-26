
rule Trojan_BAT_FormBook_ABON_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ABON!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_03_0 = {09 11 08 08 11 08 9a 1f 10 28 ?? 00 00 06 d2 } //2
		$a_01_1 = {53 79 73 74 65 6d 46 69 6c 65 4d 61 6e 61 67 65 72 2e 49 41 53 49 4a 48 55 2e 72 65 73 6f 75 72 63 65 73 } //2 SystemFileManager.IASIJHU.resources
		$a_01_2 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_01_3 = {53 70 6c 69 74 } //1 Split
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}