
rule Trojan_Win32_Amadey_MB_MTB{
	meta:
		description = "Trojan:Win32/Amadey.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {8b c8 6a 01 6a 00 6a 03 6a 00 6a 00 8d 45 08 89 8d 94 fb ff ff 0f 43 45 08 6a 50 50 51 ff 15 } //02 00 
		$a_01_1 = {44 3a 5c 4d 6b 74 6d 70 5c 41 6d 61 64 65 79 5c 52 65 6c 65 61 73 65 5c 41 6d 61 64 65 79 2e 70 64 62 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Amadey_MB_MTB_2{
	meta:
		description = "Trojan:Win32/Amadey.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {68 60 cc 42 00 e8 c5 85 01 00 59 c3 cc cc cc cc 68 00 cc 42 00 e8 b5 85 01 00 59 c3 cc cc cc cc 6a 20 68 dc 53 43 00 b9 8c ab 43 00 e8 } //02 00 
		$a_01_1 = {41 6d 61 64 65 79 2e 70 64 62 } //02 00 
		$a_01_2 = {43 72 65 61 74 65 4d 75 74 65 78 57 } //02 00 
		$a_01_3 = {6e 62 76 65 65 6b 2e 65 78 65 } //01 00 
		$a_01_4 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //00 00 
	condition:
		any of ($a_*)
 
}