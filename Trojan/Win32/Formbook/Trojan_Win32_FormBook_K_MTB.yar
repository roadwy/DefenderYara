
rule Trojan_Win32_FormBook_K_MTB{
	meta:
		description = "Trojan:Win32/FormBook.K!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 02 00 "
		
	strings :
		$a_00_0 = {31 04 1f 89 } //01 00 
		$a_00_1 = {b8 69 5d 3f 99 } //03 00 
		$a_00_2 = {81 f7 3a ac ce f1 } //03 00 
		$a_02_3 = {8b 34 0a 0f 64 d5 90 02 41 81 f6 90 02 50 89 34 08 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}