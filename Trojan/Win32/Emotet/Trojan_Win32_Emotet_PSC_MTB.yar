
rule Trojan_Win32_Emotet_PSC_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PSC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b6 44 04 90 01 01 03 c1 b9 90 01 04 99 f7 f9 8b 44 24 90 01 01 8a 4c 14 90 01 01 30 08 90 00 } //01 00 
		$a_81_1 = {68 57 73 4a 4c 71 6d 42 39 4d 31 61 5a 73 64 69 6b 79 50 46 34 31 37 48 56 75 64 4a 45 75 63 35 67 31 } //00 00 
	condition:
		any of ($a_*)
 
}