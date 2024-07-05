
rule Trojan_Win32_FormBook_AFM_MTB{
	meta:
		description = "Trojan:Win32/FormBook.AFM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 44 24 0c 03 c1 89 44 24 10 8b c1 99 6a 0c 5e f7 fe 8b 74 24 10 8a 82 90 01 04 30 06 41 3b cf 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_FormBook_AFM_MTB_2{
	meta:
		description = "Trojan:Win32/FormBook.AFM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 f6 89 f6 89 f6 89 f6 89 f6 8b 4d fc 03 cf 89 f6 89 f6 8a 10 89 f6 89 f6 89 f6 89 f6 32 55 fa 88 11 89 f6 8a 55 fb 30 11 89 f6 89 f6 89 f6 89 f6 47 40 4e } //00 00 
	condition:
		any of ($a_*)
 
}