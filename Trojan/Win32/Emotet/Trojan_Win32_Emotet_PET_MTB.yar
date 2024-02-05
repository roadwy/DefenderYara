
rule Trojan_Win32_Emotet_PET_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PET!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8a 0c 02 8b 54 24 90 01 01 32 4c 14 90 01 01 83 c0 01 83 6c 24 90 01 01 01 88 48 ff 89 44 24 90 09 08 00 8b 44 24 90 01 01 8b 54 24 90 00 } //01 00 
		$a_81_1 = {44 7d 59 24 7b 45 6c 50 44 71 67 56 35 38 25 62 4b 54 39 34 25 47 4a 50 4f 51 45 39 43 6e 41 75 68 53 7a 6e 63 48 70 46 76 75 66 44 34 25 6a 72 51 64 49 30 38 6f 30 41 74 36 69 24 4e 3f 61 4c 44 41 61 4e 24 } //00 00 
	condition:
		any of ($a_*)
 
}