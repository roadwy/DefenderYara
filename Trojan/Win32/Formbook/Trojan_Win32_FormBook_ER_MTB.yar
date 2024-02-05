
rule Trojan_Win32_FormBook_ER_MTB{
	meta:
		description = "Trojan:Win32/FormBook.ER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 03 00 "
		
	strings :
		$a_01_0 = {8b 45 f0 31 c9 c7 04 24 00 00 00 00 89 44 24 04 c7 44 24 08 00 30 00 00 c7 44 24 0c 40 00 00 00 } //02 00 
		$a_01_1 = {89 45 e8 c7 04 24 80 74 d2 1a } //00 00 
	condition:
		any of ($a_*)
 
}