
rule Trojan_Win32_Farfli_ME_MTB{
	meta:
		description = "Trojan:Win32/Farfli.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 05 00 "
		
	strings :
		$a_03_0 = {c6 45 ed 53 c6 45 ee 48 c6 45 ef 45 c6 45 f0 4c c6 45 f1 4c c6 45 f2 2e c6 45 f3 54 c6 45 f4 58 c6 45 f5 54 c6 45 f6 00 8d 4d dc 51 68 90 01 04 e8 90 00 } //03 00 
		$a_01_1 = {53 00 75 00 70 00 65 00 72 00 4d 00 61 00 72 00 6b 00 65 00 74 00 73 00 2e 00 45 00 58 00 45 00 } //01 00 
		$a_01_2 = {53 65 74 43 61 70 74 75 72 65 } //01 00 
		$a_01_3 = {53 63 72 65 65 6e 54 6f 43 6c 69 65 6e 74 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Farfli_ME_MTB_2{
	meta:
		description = "Trojan:Win32/Farfli.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {57 8b 7c 24 0c 33 c9 85 ff 7e 90 01 01 53 56 8b 74 24 10 8b c1 bb 03 00 00 00 99 f7 fb 8a 04 31 83 fa 01 75 90 01 01 3c 20 7e 90 01 01 3c 7f 7d 90 01 01 fe c8 eb 90 01 01 3c 20 7e 90 01 01 3c 7f 7d 90 01 01 fe c0 88 04 31 41 3b cf 7c 90 00 } //01 00 
		$a_03_1 = {b9 41 00 00 00 33 c0 8d 7c 24 64 8d 54 24 64 f3 ab bf 90 01 04 83 c9 ff f2 ae f7 d1 2b f9 c7 44 24 60 00 00 00 00 8b c1 8b f7 8b fa c1 e9 02 f3 a5 8b c8 33 c0 83 e1 03 f3 a4 8d 7c 24 64 83 c9 ff f2 ae f7 d1 49 51 8d 4c 24 68 51 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}