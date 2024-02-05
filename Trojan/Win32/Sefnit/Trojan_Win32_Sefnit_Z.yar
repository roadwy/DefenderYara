
rule Trojan_Win32_Sefnit_Z{
	meta:
		description = "Trojan:Win32/Sefnit.Z,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {eb 1d 83 fe 01 75 18 c7 45 fc 0c 00 00 00 e8 } //01 00 
		$a_01_1 = {68 06 02 00 00 53 8d 85 ca 00 00 00 50 e8 } //01 00 
		$a_01_2 = {2f 67 65 74 38 00 } //01 00 
		$a_01_3 = {47 30 74 44 30 6f 63 6d 64 00 } //01 00 
		$a_01_4 = {38 38 2e 31 39 38 2e 32 33 38 2e 31 33 2f } //01 00 
		$a_01_5 = {36 32 2e 31 30 39 2e 32 31 2e 39 30 2f } //00 00 
	condition:
		any of ($a_*)
 
}