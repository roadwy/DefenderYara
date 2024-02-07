
rule Trojan_Win32_Vrodirb_B{
	meta:
		description = "Trojan:Win32/Vrodirb.B,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 05 00 00 02 00 "
		
	strings :
		$a_03_0 = {8b 44 24 04 8b 54 24 08 f7 40 04 06 00 00 00 74 90 01 01 8b 4a 04 c7 42 04 90 01 02 40 00 53 56 57 55 8b 6a 08 83 c1 05 e8 90 01 02 ff ff ff d1 90 00 } //01 00 
		$a_02_1 = {2f 3f 44 6c 6c 90 02 04 49 45 46 72 61 6d 65 90 00 } //01 00 
		$a_02_2 = {42 52 5f 46 52 41 4d 45 90 02 04 58 41 64 64 72 42 61 72 90 00 } //01 00 
		$a_02_3 = {43 3a 5c 4e 90 02 04 5c 63 74 66 6d 6f 6e 2e 65 78 65 90 00 } //01 00 
		$a_00_4 = {75 73 70 31 30 2e 64 6c 6c } //00 00  usp10.dll
	condition:
		any of ($a_*)
 
}