
rule Trojan_Win32_FormBook_AFB_MTB{
	meta:
		description = "Trojan:Win32/FormBook.AFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {50 ff d6 68 90 01 04 53 a3 08 c9 43 00 ff d7 50 ff d6 68 90 01 04 53 a3 0c c9 43 00 ff d7 50 ff d6 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_FormBook_AFB_MTB_2{
	meta:
		description = "Trojan:Win32/FormBook.AFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 f6 33 c9 b8 90 01 04 f7 e9 c1 fa 90 01 01 8b c2 c1 e8 90 01 01 03 c2 8d 04 80 03 c0 03 c0 8b d1 2b d0 8a 04 3a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}