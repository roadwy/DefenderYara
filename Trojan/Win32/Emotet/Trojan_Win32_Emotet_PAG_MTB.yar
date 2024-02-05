
rule Trojan_Win32_Emotet_PAG_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 00 6a 00 0f b6 04 08 0f b6 0c 0a 33 d2 03 c1 b9 90 02 04 f7 f1 8a da ff 90 01 01 6a 00 6a 00 ff 90 01 01 a1 90 01 04 8b f7 2b 35 90 01 04 0f b6 cb 8a 04 01 8b 4d 90 01 01 30 04 0e 47 be 90 01 04 8b 4d 90 01 01 3b 7d 90 01 01 0f 8c 90 01 04 8b 7d 90 01 01 8a 45 90 01 01 5e 88 3f 88 47 90 01 01 5f 5b c9 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Emotet_PAG_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.PAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {6a 0a 8b 01 8b 40 90 01 01 ff d0 0f b6 c0 8b ce 50 e8 90 02 04 8b ce e8 90 02 04 a1 90 02 04 8b d7 0f b6 90 02 04 47 2b 15 90 02 04 8a 04 01 b9 90 01 02 00 00 30 04 1a 8b 45 90 01 01 3b 7d 90 01 01 0f 8c 90 00 } //01 00 
		$a_01_1 = {58 00 62 00 6c 00 40 00 59 00 63 00 6d 00 41 00 5a 00 64 00 6e 00 42 00 5b 00 65 00 6f 00 43 00 5c 00 66 00 70 00 44 00 5d 00 67 00 71 00 } //00 00 
		$a_00_2 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}