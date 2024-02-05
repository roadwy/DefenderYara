
rule Trojan_Win32_Khalesi_DAL_MTB{
	meta:
		description = "Trojan:Win32/Khalesi.DAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {3e 42 4c bd 8c 3e 36 20 31 8e 9e 8c a9 83 1c 4f 0c 0d 4b b2 fd 47 6b 01 cb 61 f1 6e 68 4e b2 cb 39 e6 4f 95 8d 6e 9d b8 f2 8a 43 9d c5 49 ee 9b 78 } //01 00 
		$a_01_1 = {bb f0 70 5e c4 b4 1b 36 ed 3c 4f 68 5d ba 95 49 b4 83 13 c0 25 b0 d3 81 8a 34 68 4b 57 7f } //01 00 
		$a_01_2 = {32 b3 75 6a 3f 3f 02 2c 2c 2c 23 89 bf 3e 88 1d b2 0f a9 98 37 22 56 a8 e6 e6 f9 32 3f } //01 00 
		$a_01_3 = {4c 2b 86 79 94 d4 da 31 6a 91 02 02 02 02 02 53 53 92 c2 52 85 7c } //00 00 
	condition:
		any of ($a_*)
 
}