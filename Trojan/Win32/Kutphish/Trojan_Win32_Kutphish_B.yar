
rule Trojan_Win32_Kutphish_B{
	meta:
		description = "Trojan:Win32/Kutphish.B,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {6d 00 73 00 69 00 65 00 78 00 65 00 63 00 90 02 30 2d 00 69 00 90 02 10 68 00 74 00 74 00 70 00 90 00 } //01 00 
		$a_02_1 = {6d 00 73 00 69 00 65 00 78 00 65 00 63 00 90 02 30 2f 00 69 00 90 02 10 68 00 74 00 74 00 70 00 90 00 } //06 00 
	condition:
		any of ($a_*)
 
}