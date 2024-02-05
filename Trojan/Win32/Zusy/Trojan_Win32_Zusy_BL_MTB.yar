
rule Trojan_Win32_Zusy_BL_MTB{
	meta:
		description = "Trojan:Win32/Zusy.BL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 74 6f 6e 65 2c 49 20 68 61 74 65 20 79 6f 75 21 } //01 00 
		$a_01_1 = {59 6f 75 72 20 64 69 73 6b 20 69 73 20 72 65 6d 6f 76 65 64 21 } //01 00 
		$a_01_2 = {43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 41 64 76 61 6e 63 65 64 5c 46 6f 6c 64 65 72 5c 48 69 64 64 65 6e 5c 53 48 4f 57 41 4c 4c } //01 00 
		$a_01_3 = {5c 41 75 74 6f 52 75 6e 2e 65 78 65 } //01 00 
		$a_01_4 = {45 d8 8b 55 f8 8b 4d f4 8a 54 0a ff e8 53 8b fa ff 8d 45 d8 ba dc b8 45 00 e8 26 8c fa ff 8b 45 d8 8d 55 dc e8 bb ca fa ff 8b 4d dc b2 01 a1 } //00 00 
	condition:
		any of ($a_*)
 
}