
rule Trojan_Win32_Emotet_MA_MTB{
	meta:
		description = "Trojan:Win32/Emotet.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 55 f4 83 c2 01 89 55 f4 8b 45 f4 3b 45 10 73 90 01 01 8b 4d fc 03 4d f4 8b 55 f8 03 55 f4 8a 02 88 01 eb 90 00 } //01 00 
		$a_03_1 = {8b 4d ec 8b 55 f0 03 51 0c 89 55 f8 8b 45 ec 8b 48 10 51 8b 55 ec 8b 45 08 03 42 14 50 8b 4d f8 51 e8 90 01 04 83 c4 0c 8b 55 ec 8b 45 f8 89 42 08 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}