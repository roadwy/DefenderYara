
rule Trojan_BAT_Barys_SK_MTB{
	meta:
		description = "Trojan:BAT/Barys.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {24 38 62 35 32 65 66 38 66 2d 36 31 62 33 2d 34 63 65 33 2d 38 63 65 65 2d 36 31 39 39 65 66 63 32 39 37 38 36 } //1 $8b52ef8f-61b3-4ce3-8cee-6199efc29786
		$a_81_1 = {5a 65 75 73 43 72 79 70 74 65 72 5c 6f 62 6a 5c 44 65 62 75 67 5c 5a 65 75 73 43 72 79 70 74 65 72 2e 70 64 62 } //1 ZeusCrypter\obj\Debug\ZeusCrypter.pdb
		$a_81_2 = {57 72 69 74 65 20 70 61 74 68 20 74 6f 20 66 69 6c 65 20 74 6f 20 65 6e 63 72 79 70 74 } //1 Write path to file to encrypt
		$a_81_3 = {43 72 79 70 74 65 64 2e 65 78 65 } //1 Crypted.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}