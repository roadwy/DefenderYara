
rule Trojan_Win32_Emotet_PEC_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PEC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b6 cb 03 c1 8b ce 99 f7 f9 8b 45 90 01 01 8a 9c 15 90 01 04 32 18 90 00 } //01 00 
		$a_02_1 = {81 e1 ff 00 00 00 03 c1 b9 90 01 04 99 f7 f9 8a 4d 00 8a 5c 14 90 01 01 32 d9 90 09 04 00 8a 44 34 90 00 } //01 00 
		$a_81_2 = {5a 48 51 58 43 62 78 79 44 46 59 35 6a 45 50 44 39 79 39 57 51 41 67 76 42 69 7a 41 68 53 5a 69 52 32 53 31 72 } //00 00 
	condition:
		any of ($a_*)
 
}