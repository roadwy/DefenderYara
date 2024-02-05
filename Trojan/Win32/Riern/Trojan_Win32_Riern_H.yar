
rule Trojan_Win32_Riern_H{
	meta:
		description = "Trojan:Win32/Riern.H,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 0c 32 32 cb 88 0c 2e 46 3b 74 24 90 01 01 0f 8c 90 01 04 5b 90 00 } //01 00 
		$a_03_1 = {8b c8 88 1c 29 89 7e 90 01 01 5d 39 56 90 01 01 72 02 8b 00 c6 04 38 00 8b c6 90 00 } //01 00 
		$a_01_2 = {8d 68 01 8d 49 00 8a 08 40 3a cb 75 f9 2b c5 50 } //01 00 
		$a_03_3 = {c7 44 24 10 01 00 00 00 39 90 01 03 72 0a 8b 90 01 03 89 90 01 03 eb 08 8d 90 01 03 89 90 02 09 8d 90 01 04 6a 01 90 01 01 ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}