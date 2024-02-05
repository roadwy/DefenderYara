
rule Trojan_Win32_Dexphot_CC{
	meta:
		description = "Trojan:Win32/Dexphot.CC,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {6d 00 73 00 69 00 65 00 78 00 65 00 63 00 90 02 20 70 00 61 00 63 00 6b 00 61 00 67 00 65 00 90 02 10 68 00 74 00 74 00 70 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}