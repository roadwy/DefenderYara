
rule Trojan_BAT_FormBook_AMO_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AMO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 08 91 09 61 07 08 17 58 07 8e 69 5d 91 13 04 11 04 59 20 00 01 00 00 58 20 ff 00 00 00 5f 13 05 07 08 11 05 28 ?? 00 00 0a 9c 08 17 58 } //2
		$a_01_1 = {45 00 6d 00 70 00 6c 00 6f 00 79 00 65 00 65 00 49 00 6e 00 66 00 6f 00 41 00 70 00 70 00 } //1 EmployeeInfoApp
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}