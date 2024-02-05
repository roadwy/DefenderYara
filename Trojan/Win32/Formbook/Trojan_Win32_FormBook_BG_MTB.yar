
rule Trojan_Win32_FormBook_BG_MTB{
	meta:
		description = "Trojan:Win32/FormBook.BG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b cf b2 46 8a 03 90 18 32 c2 88 01 90 02 10 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}