
rule Trojan_MacOS_Rakkotonak_A{
	meta:
		description = "Trojan:MacOS/Rakkotonak.A,SIGNATURE_TYPE_MACHOHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 00 32 03 88 45 90 09 04 00 48 8b 45 90 01 05 88 45 90 01 01 48 8d 55 90 01 01 b9 01 00 00 00 4c 89 e6 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}