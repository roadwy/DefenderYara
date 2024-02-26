
rule Trojan_Win32_FormBook_PRF_MTB{
	meta:
		description = "Trojan:Win32/FormBook.PRF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {88 18 40 83 ee 01 75 f8 33 c9 8a 81 08 90 01 01 42 00 c0 c8 03 32 83 70 e4 41 00 88 81 08 90 1b 00 42 00 8d 43 01 6a 0d 99 5e f7 fe 41 b8 90 01 02 00 00 8b da 3b c8 72 d6 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}