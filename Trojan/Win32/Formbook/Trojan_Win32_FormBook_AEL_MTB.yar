
rule Trojan_Win32_FormBook_AEL_MTB{
	meta:
		description = "Trojan:Win32/FormBook.AEL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 4d 10 8a 04 39 04 22 34 6d 2c 61 34 cf fe c8 34 15 2c 36 88 04 39 47 3b fb } //2
		$a_01_1 = {43 72 65 61 74 65 46 69 6c 65 57 } //1 CreateFileW
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}