
rule Trojan_Win32_FormBook_MBT_MTB{
	meta:
		description = "Trojan:Win32/FormBook.MBT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 04 37 04 22 34 3b fe c8 34 ee 04 74 34 bf 04 63 88 04 37 46 3b f3 72 e7 } //1
		$a_01_1 = {68 00 30 00 00 8b d8 53 6a 00 ff d7 8b 55 10 6a 00 8d 4d fc 51 53 8b f8 57 52 ff 15 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}