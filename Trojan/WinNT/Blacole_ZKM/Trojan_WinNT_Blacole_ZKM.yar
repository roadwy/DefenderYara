
rule Trojan_WinNT_Blacole_ZKM{
	meta:
		description = "Trojan:WinNT/Blacole_ZKM,SIGNATURE_TYPE_JAVAHSTR_EXT,02 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {11 10 00 bc 08 3a 90 01 01 03 36 0a 90 00 } //01 00 
		$a_03_1 = {10 41 10 5a b6 90 01 02 36 04 90 02 2a 10 41 a1 ff 90 00 } //01 00 
		$a_01_2 = {10 5a 36 0a 10 4d 36 } //01 00 
		$a_01_3 = {a7 00 04 bf } //00 00 
	condition:
		any of ($a_*)
 
}