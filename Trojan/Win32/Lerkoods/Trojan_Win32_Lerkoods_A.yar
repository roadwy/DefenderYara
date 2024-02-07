
rule Trojan_Win32_Lerkoods_A{
	meta:
		description = "Trojan:Win32/Lerkoods.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 43 04 c6 43 08 b8 8b 45 08 89 43 09 66 c7 43 0d ff e0 } //01 00 
		$a_01_1 = {80 78 18 00 74 14 54 6a 08 8d 50 08 52 8b 50 1c 52 8b 40 04 50 e8 } //01 00 
		$a_01_2 = {4b 65 72 6e 65 6c 33 32 62 69 74 73 2e 64 6c 6c 00 45 6e 64 48 6f 6f 6b 73 00 53 74 61 72 74 48 6f 6f 6b 00 } //00 00  敋湲汥㈳楢獴搮汬䔀摮潈歯s瑓牡䡴潯k
	condition:
		any of ($a_*)
 
}