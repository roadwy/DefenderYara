
rule Trojan_BAT_RevengeRat_UXA_MTB{
	meta:
		description = "Trojan:BAT/RevengeRat.UXA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {73 19 00 00 0a 0b 73 19 00 00 0a 0c 02 28 90 01 03 06 03 15 17 28 90 01 03 0a 0d 07 02 16 09 16 9a 6f 90 00 } //01 00 
		$a_01_1 = {53 00 65 00 6c 00 65 00 63 00 74 00 20 00 2a 00 20 00 66 00 72 00 6f 00 6d 00 20 00 41 00 6e 00 74 00 69 00 56 00 69 00 72 00 75 00 73 00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00 } //01 00  Select * from AntiVirusProduct
		$a_01_2 = {53 00 45 00 4c 00 45 00 43 00 54 00 20 00 2a 00 20 00 46 00 52 00 4f 00 4d 00 20 00 46 00 69 00 72 00 65 00 77 00 61 00 6c 00 6c 00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00 } //00 00  SELECT * FROM FirewallProduct
	condition:
		any of ($a_*)
 
}