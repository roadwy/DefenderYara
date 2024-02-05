
rule Trojan_WinNT_Flosyt_A{
	meta:
		description = "Trojan:WinNT/Flosyt.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 48 08 8b 00 8b 15 90 01 04 3b 54 88 fc 74 04 e2 f8 eb 0f 8d 44 88 fc a3 90 01 04 c7 00 90 00 } //01 00 
		$a_03_1 = {83 7c 24 04 05 75 0e 8b 74 24 08 8b 3c 24 c7 04 24 90 01 04 ff 25 90 01 04 85 c0 75 90 01 01 eb 90 01 01 03 36 39 46 3c 74 90 01 01 8b 56 3c 81 3a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}