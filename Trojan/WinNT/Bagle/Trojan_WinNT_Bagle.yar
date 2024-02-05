
rule Trojan_WinNT_Bagle{
	meta:
		description = "Trojan:WinNT/Bagle,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 75 28 03 75 18 8b 4d 2c 90 03 01 01 eb e9 90 00 } //01 00 
		$a_00_1 = {80 36 33 46 49 0b c9 75 f7 } //00 00 
	condition:
		any of ($a_*)
 
}