
rule Trojan_Win32_ReadlineStealer_BZ_MTB{
	meta:
		description = "Trojan:Win32/ReadlineStealer.BZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 05 00 "
		
	strings :
		$a_01_0 = {51 83 65 fc 00 8b 45 10 01 45 fc 8b 45 fc 33 45 0c 8b 4d 08 89 01 } //05 00 
		$a_01_1 = {c1 e8 05 03 45 d8 c1 e1 04 03 4d e4 50 03 d6 8d 45 0c 33 ca 50 } //01 00 
		$a_01_2 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00 
		$a_01_3 = {4f 70 65 6e 4d 75 74 65 78 } //01 00 
		$a_01_4 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //00 00 
	condition:
		any of ($a_*)
 
}