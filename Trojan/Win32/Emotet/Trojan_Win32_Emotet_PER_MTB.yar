
rule Trojan_Win32_Emotet_PER_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8a 14 01 8b 4c 24 90 01 01 32 54 0c 90 01 01 40 88 50 ff 89 44 24 90 09 08 00 8b 44 24 90 01 01 8b 4c 24 90 00 } //01 00 
		$a_81_1 = {6a 57 35 66 31 4a 4e 42 66 44 75 75 24 39 4e 72 7c 77 36 68 39 64 53 30 31 64 7b 58 4f 31 51 7b 7e 78 57 2a 64 49 6f 63 5a 79 5a 42 53 47 35 30 7e 7b 4a 4f 44 40 35 47 50 4c 4b 40 64 58 54 50 69 46 70 7c 25 31 4c 32 30 72 44 42 72 51 42 39 } //00 00 
	condition:
		any of ($a_*)
 
}