
rule Trojan_Win32_CryptInject_RI_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.RI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {4e 75 6c 6c 73 6f 66 74 20 49 6e 73 74 61 6c 6c 20 53 79 73 74 65 6d } //05 00 
		$a_03_1 = {25 25 5c 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 90 02 0f 2c 58 79 6c 6f 6c 90 0a 3f 00 90 1b 00 2e 64 6c 6c 90 00 } //01 00 
		$a_01_2 = {43 61 6e 27 74 20 69 6e 69 74 69 61 6c 69 7a 65 20 70 6c 75 67 2d 69 6e 73 20 64 69 72 65 63 74 6f 72 79 } //01 00 
		$a_01_3 = {43 6f 72 72 75 70 74 65 64 20 69 6e 73 74 61 6c 6c 65 72 3f } //01 00 
		$a_01_4 = {45 78 65 63 75 74 65 3a } //01 00 
		$a_01_5 = {24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e } //00 00 
	condition:
		any of ($a_*)
 
}