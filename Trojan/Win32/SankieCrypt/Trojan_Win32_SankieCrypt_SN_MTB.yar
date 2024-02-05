
rule Trojan_Win32_SankieCrypt_SN_MTB{
	meta:
		description = "Trojan:Win32/SankieCrypt.SN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 65 6e 74 77 73 33 61 78 2e 63 31 2e 62 69 7a 2f 67 61 74 65 2e 70 68 70 } //01 00 
		$a_01_1 = {68 74 74 70 3a 2f 2f 35 6e 64 69 73 6a 74 75 2e 63 31 2e 62 69 7a 2f 73 74 61 72 74 2e 70 68 70 3f 75 73 72 3d 25 31 26 63 6d 70 3d 25 32 26 6b 3d 25 33 } //01 00 
		$a_01_2 = {2d 2d 2d 2d 48 69 48 74 54 70 43 6c 49 65 4e 74 } //01 00 
		$a_01_3 = {68 74 74 70 3a 2f 2f 35 6e 64 69 73 6a 74 75 2e 63 31 2e 62 69 7a 2f 64 61 74 61 2f 67 65 74 2e 70 68 70 } //00 00 
	condition:
		any of ($a_*)
 
}