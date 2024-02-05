
rule Trojan_MacOS_GetShell_B{
	meta:
		description = "Trojan:MacOS/GetShell.B,SIGNATURE_TYPE_MACHOHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_00_0 = {6a 00 5f 68 00 10 00 00 5e 6a 07 5a 68 02 10 00 00 41 5a 6a 00 41 58 6a 00 41 59 68 c5 00 00 02 } //00 00 
	condition:
		any of ($a_*)
 
}