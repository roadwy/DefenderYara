
rule Trojan_Win32_FormBook_BX_MTB{
	meta:
		description = "Trojan:Win32/FormBook.BX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {8a 04 02 88 45 } //01 00 
		$a_02_1 = {33 d2 8a 55 90 01 01 33 c2 90 02 20 90 13 90 02 10 8b 55 90 01 01 88 02 90 02 20 ff 45 90 02 10 ff 4d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}