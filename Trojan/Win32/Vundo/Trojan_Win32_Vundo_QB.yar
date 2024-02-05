
rule Trojan_Win32_Vundo_QB{
	meta:
		description = "Trojan:Win32/Vundo.QB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 64 66 63 6c 69 63 6b 3b 61 6c 6c 2e 68 74 6d 6c 3b 61 72 74 69 63 6c 65 2e 61 73 70 3b 42 6f 78 52 65 64 69 72 65 63 74 2e 73 68 74 6d 6c 3b } //01 00 
		$a_01_1 = {72 65 66 65 72 65 72 50 61 67 65 3b 52 45 46 45 52 52 41 4c 49 44 3b 52 4d 49 44 3b 52 4e 4c 42 53 45 52 56 45 52 49 44 3b 72 75 69 64 3b 72 76 64 3b 53 3b 73 3b 53 42 53 45 53 53 49 4f 4e 49 44 3b 53 45 53 53 49 44 3b } //0a 00 
		$a_03_2 = {80 bc 05 c3 fe ff ff 5c 75 1d 8d 85 90 01 01 fe ff ff 8d 50 01 8d 64 24 00 8a 08 40 84 c9 75 f9 2b c2 88 8c 05 c3 fe ff ff 8d 8d 90 01 01 fe ff ff e8 95 fe ff ff 89 85 90 01 01 fe ff ff 89 95 90 01 01 fe ff ff 90 00 } //0a 00 
		$a_03_3 = {52 6a 06 56 ff 15 90 01 04 89 5d e4 6a 04 8d 45 e4 50 6a 07 56 ff 15 90 01 04 89 7d e4 6a 04 8d 4d e4 51 6a 05 56 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}