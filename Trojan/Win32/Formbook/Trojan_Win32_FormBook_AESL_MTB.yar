
rule Trojan_Win32_FormBook_AESL_MTB{
	meta:
		description = "Trojan:Win32/FormBook.AESL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {8a 04 37 34 4e 2c 74 34 55 88 04 37 46 3b f3 72 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 46 69 6c 65 57 } //00 00  CreateFileW
	condition:
		any of ($a_*)
 
}