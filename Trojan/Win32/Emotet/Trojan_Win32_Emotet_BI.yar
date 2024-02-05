
rule Trojan_Win32_Emotet_BI{
	meta:
		description = "Trojan:Win32/Emotet.BI,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 44 24 2c 8b 8c 24 90 01 04 81 f1 19 ff a4 32 89 c2 21 ca 8a 1c 05 90 01 04 2a 1c 15 90 01 04 8b 8c 24 90 01 04 81 c1 eb 00 5b cd 88 5c 04 3c 01 c8 89 44 24 2c 83 f8 18 90 00 } //01 00 
		$a_01_1 = {31 c9 89 54 24 10 89 ca 8b 4c 24 14 f7 f1 8a 3c 16 28 fb 8b 54 24 10 81 e2 ff 00 00 00 8a 4c 14 48 80 c1 01 8b 74 24 1c 88 1c 3e 30 f9 88 4c 14 48 } //00 00 
	condition:
		any of ($a_*)
 
}