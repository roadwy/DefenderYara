
rule Trojan_Win32_Squibda_A{
	meta:
		description = "Trojan:Win32/Squibda.A,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {77 00 6d 00 69 00 63 00 2e 00 65 00 78 00 65 00 90 02 30 66 00 6f 00 72 00 6d 00 61 00 74 00 3a 00 90 02 03 68 00 74 00 74 00 70 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}