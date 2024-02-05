
rule Trojan_Win32_Kutphish_F{
	meta:
		description = "Trojan:Win32/Kutphish.F,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {6d 00 73 00 69 00 65 00 78 00 65 00 63 00 90 02 20 2d 00 7a 00 20 00 90 00 } //01 00 
		$a_02_1 = {6d 00 73 00 69 00 65 00 78 00 65 00 63 00 90 02 20 2f 00 7a 00 20 00 90 00 } //05 00 
	condition:
		any of ($a_*)
 
}