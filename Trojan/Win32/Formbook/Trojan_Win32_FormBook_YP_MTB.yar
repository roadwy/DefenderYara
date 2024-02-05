
rule Trojan_Win32_FormBook_YP_MTB{
	meta:
		description = "Trojan:Win32/FormBook.YP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {88 02 83 45 90 01 04 e8 90 01 04 ff 45 90 01 01 41 81 7d 90 02 10 90 13 8a 01 34 90 01 01 88 45 90 01 01 8b 55 90 01 01 8a 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}