
rule Trojan_Win32_Emotet_PES_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PES!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8a 14 01 8b 4c 24 90 01 01 32 54 0c 90 01 01 88 10 40 89 44 24 90 09 08 00 8b 44 24 90 01 01 8b 4c 24 90 00 } //01 00 
		$a_81_1 = {4b 62 56 76 55 6b 73 64 70 4b 73 50 31 62 4e 5a 6b 6f 51 6f 57 40 52 24 33 72 70 2a 7b 58 7e 39 2a 51 32 6b 30 71 2a 52 6d 57 52 63 65 76 44 59 47 36 25 57 7e 63 4e 65 4b 4e 47 5a 24 47 38 2a 32 55 30 2a 33 63 36 77 33 4d 23 3f 45 } //00 00 
	condition:
		any of ($a_*)
 
}