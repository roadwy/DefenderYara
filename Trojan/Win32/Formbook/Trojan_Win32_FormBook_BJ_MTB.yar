
rule Trojan_Win32_FormBook_BJ_MTB{
	meta:
		description = "Trojan:Win32/FormBook.BJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {39 c2 0f b7 c9 90 02 25 90 13 90 02 25 46 90 02 25 8b 17 90 02 20 90 18 90 02 20 0f 6e da 90 02 20 31 f2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}