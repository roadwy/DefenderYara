
rule Trojan_Win32_Emotet_PBF_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PBF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8a 04 33 03 c1 f7 35 90 01 04 8b 44 24 90 01 01 8a 0c 28 8a 14 32 32 d1 8b 4c 24 90 01 01 88 14 29 90 00 } //01 00 
		$a_81_1 = {24 68 6a 25 6b 30 47 41 32 3f 32 2a 49 38 71 53 4d 45 33 35 25 79 4c 68 4b 30 35 46 41 4c 31 66 67 59 7a 7e 70 25 43 42 7e 37 63 52 6f 38 34 47 73 61 4e 48 52 6f 63 6a 68 37 6b 68 58 51 33 69 51 32 79 7c 3f 4b 23 59 50 71 74 } //00 00 
	condition:
		any of ($a_*)
 
}