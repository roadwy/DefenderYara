
rule Trojan_Win32_Emotet_PVQ_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PVQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b6 4c 24 17 03 c1 99 b9 df 08 00 00 f7 f9 8b 4c 24 20 8b 84 24 90 01 04 8a 54 14 24 30 14 01 90 00 } //01 00 
		$a_00_1 = {6d 66 35 44 6a 6a 34 63 62 49 79 6c 71 64 51 77 5a 4e 77 6e 48 38 77 43 5a 46 33 75 76 34 32 34 7a 79 64 36 79 65 67 } //00 00 
	condition:
		any of ($a_*)
 
}