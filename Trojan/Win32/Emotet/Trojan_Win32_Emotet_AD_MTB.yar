
rule Trojan_Win32_Emotet_AD_MTB{
	meta:
		description = "Trojan:Win32/Emotet.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {31 f6 2b 30 f7 de 83 c0 90 01 01 83 ee 90 01 01 01 fe 83 c6 90 01 01 8d 3e c7 01 00 00 00 00 09 31 83 c1 04 83 c3 04 81 fb 90 01 04 75 90 01 01 59 ff 35 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Emotet_AD_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8a 24 0a 8b 54 24 90 01 01 8a 5c 24 90 01 01 c7 44 24 90 01 01 00 00 00 00 c7 44 24 90 01 01 00 00 00 00 01 ce b7 31 28 df 30 f8 00 c4 90 00 } //01 00 
		$a_02_1 = {8b 44 24 04 8a 4c 24 90 01 01 88 08 8d 65 90 01 01 5e 5f 5b 5d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Emotet_AD_MTB_3{
	meta:
		description = "Trojan:Win32/Emotet.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 45 f8 81 75 f8 90 01 04 8a 4d f8 8b 75 fc c7 45 f8 90 00 } //01 00 
		$a_03_1 = {89 45 f8 c1 65 f8 04 81 75 f8 90 01 04 8a 4d f8 8b 55 fc 0f be 03 89 45 fc 90 00 } //01 00 
		$a_01_2 = {01 75 fc d3 e2 01 55 fc } //01 00 
		$a_01_3 = {29 7d fc 43 80 3b 00 75 a4 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Emotet_AD_MTB_4{
	meta:
		description = "Trojan:Win32/Emotet.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 08 00 00 01 00 "
		
	strings :
		$a_02_0 = {69 72 74 75 75 6c 41 6c 6c 6f 63 90 01 03 72 6e 65 6c 33 32 2e 64 6c 6c 90 00 } //ff ff 
		$a_01_1 = {76 69 72 74 75 61 6c 41 6c 6c 6f 63 00 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c } //01 00 
		$a_02_2 = {ff 36 5f 83 ee fc 83 c7 90 01 01 01 cf 83 ef 90 01 01 29 c9 49 21 f9 c6 03 00 09 3b 83 c3 04 83 c2 04 81 fa 90 01 04 75 90 01 01 5b ff 35 90 01 04 68 90 01 04 ff e3 90 00 } //01 00 
		$a_02_3 = {ff 32 58 83 c2 04 83 c0 de 01 c8 83 c0 90 01 01 50 59 c6 03 00 09 03 83 c3 90 01 01 83 c6 90 01 01 83 fe 90 01 01 75 90 01 01 5b ff 35 90 01 04 ff d3 90 00 } //01 00 
		$a_02_4 = {ff 36 5f 83 ee fc 83 c7 de 01 cf 83 ef 90 01 01 29 c9 49 21 f9 c6 03 00 09 3b 83 c3 04 83 c2 04 81 fa 90 01 04 75 90 01 01 5b ff 35 90 01 04 ff d3 90 00 } //01 00 
		$a_02_5 = {8b 33 83 c3 04 83 ee 22 8d 34 06 83 c6 ff 29 c0 29 f0 f7 d8 c6 07 00 01 37 83 c7 04 83 c1 04 8d 35 90 01 04 81 c6 90 01 04 56 c3 90 00 } //01 00 
		$a_02_6 = {31 db 2b 1a f7 db 83 ea fc 83 c3 de 8d 1c 33 83 eb 01 8d 33 c6 07 00 01 1f 83 ef fc 83 c1 fc 83 f9 00 75 90 01 01 5f ff 35 90 01 04 68 90 01 04 57 90 00 } //01 00 
		$a_02_7 = {29 d2 2b 16 f7 da 83 ee fc 83 ea 22 8d 14 1a 8d 52 ff 89 d3 c6 07 00 09 17 83 c7 04 83 c1 fc 8d 15 90 01 04 81 c2 90 01 04 52 90 00 } //00 00 
		$a_00_8 = {7e } //15 00  ~
	condition:
		any of ($a_*)
 
}