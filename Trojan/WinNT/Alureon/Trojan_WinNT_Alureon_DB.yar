
rule Trojan_WinNT_Alureon_DB{
	meta:
		description = "Trojan:WinNT/Alureon.DB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 70 3c 03 f0 8b 46 50 89 45 90 01 01 6a 40 68 00 30 00 00 8d 45 90 01 01 50 53 8d 45 90 01 01 50 ff 75 08 ff 15 90 00 } //01 00 
		$a_03_1 = {8b 0a 03 ce 33 ff eb 0e 0f bf 19 69 ff 90 01 04 03 fb 41 33 db 38 19 75 ee 39 7d 0c 74 90 00 } //01 00 
	condition:
		any of ($a_*)
 
}