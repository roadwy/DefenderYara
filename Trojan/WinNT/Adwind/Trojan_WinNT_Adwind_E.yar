
rule Trojan_WinNT_Adwind_E{
	meta:
		description = "Trojan:WinNT/Adwind.E,SIGNATURE_TYPE_JAVAHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 33 53 55 57 37 45 38 32 49 4b 51 4b 32 4a 32 4a 32 49 49 53 49 53 90 02 ff 6a 61 76 61 2f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}