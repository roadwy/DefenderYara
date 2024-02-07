
rule Trojan_Win32_Emotet_AR_MTB{
	meta:
		description = "Trojan:Win32/Emotet.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 45 17 59 8b 4d 10 43 ff 45 10 88 01 3b 1d 90 01 04 0f 82 90 00 } //01 00 
		$a_01_1 = {8a 04 33 8b fa 33 d2 8a 0c 37 88 04 37 88 0c 33 0f b6 04 37 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Emotet_AR_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 44 24 14 8d 2c 3b 88 1c 28 8b c3 99 f7 7c 24 2c 8b 44 24 28 43 8a 14 02 88 55 00 3b de } //01 00 
		$a_01_1 = {8b 54 24 18 0f b6 14 1a 8a 03 03 54 24 10 0f b6 c0 03 c2 33 d2 f7 f6 8a 03 43 83 6c 24 14 01 8b fa 8a 14 0f 88 04 0f 88 53 ff 89 7c 24 10 } //00 00 
		$a_00_2 = {78 } //6a 00  x
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Emotet_AR_MTB_3{
	meta:
		description = "Trojan:Win32/Emotet.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 05 00 00 01 00 "
		
	strings :
		$a_80_0 = {71 65 70 66 6a 61 6e 63 69 6b 70 6b } //qepfjancikpk  01 00 
		$a_80_1 = {6c 77 63 69 6b 6d 69 6c 74 67 6a 6a 76 6c 73 } //lwcikmiltgjjvls  01 00 
		$a_80_2 = {69 63 73 6e 62 67 73 68 61 76 62 71 70 64 } //icsnbgshavbqpd  01 00 
		$a_80_3 = {6e 62 6a 64 68 6d 72 6c 6e 6e 61 74 76 65 6f 6f } //nbjdhmrlnnatveoo  0a 00 
		$a_80_4 = {65 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c } //ekernel32.dll  00 00 
		$a_00_5 = {78 a0 00 00 03 00 03 00 04 00 00 } //01 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Emotet_AR_MTB_4{
	meta:
		description = "Trojan:Win32/Emotet.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 f0 0f b6 14 38 8a 1f 03 55 fc 0f b6 c3 03 c2 33 d2 f7 f1 8d 04 32 89 55 fc 8a 10 88 18 88 17 47 ff 4d f4 } //01 00 
		$a_03_1 = {0f b6 14 2b 8a 03 03 54 24 10 0f b6 c0 03 c2 33 d2 f7 f1 8a 03 47 43 8a 0c 32 88 04 32 88 4b ff 8b 0d 90 01 04 3b f9 89 54 24 10 90 00 } //02 00 
		$a_03_2 = {8a 0c 37 8b da 8a 04 33 88 0c 33 88 04 37 0f b6 14 33 0f b6 c0 03 c2 33 d2 f7 35 90 01 04 89 54 24 14 90 00 } //02 00 
		$a_81_3 = {54 64 66 64 67 66 73 51 72 63 67 78 67 63 } //00 00  TdfdgfsQrcgxgc
		$a_00_4 = {78 b8 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Emotet_AR_MTB_5{
	meta:
		description = "Trojan:Win32/Emotet.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 d2 f7 f1 8a 03 47 43 8a 0c 32 88 04 32 88 4b ff 8b 0d 90 01 04 3b f9 89 54 24 10 90 00 } //01 00 
		$a_01_1 = {8b 44 24 24 8b 4c 24 14 8a 14 01 8b 4c 24 18 32 14 31 40 88 50 ff 89 44 24 24 ff 4c 24 10 } //01 00 
		$a_01_2 = {8b 44 24 10 8d 34 3b 88 1c 30 8b c3 99 f7 7c 24 28 8b 44 24 24 83 c3 01 81 fb e1 18 00 00 8a 14 02 88 16 } //01 00 
		$a_01_3 = {8a 14 0f 8a 04 0e 88 14 0e 88 04 0f 0f b6 14 0e 0f b6 c0 03 c2 33 d2 f7 f5 0f b6 04 0a 8b 54 24 14 32 44 1a ff 83 6c 24 20 01 88 43 ff } //01 00 
		$a_81_4 = {6c 68 78 58 66 59 39 6d 49 72 44 5a } //00 00  lhxXfY9mIrDZ
		$a_00_5 = {7e } //15 00  ~
	condition:
		any of ($a_*)
 
}