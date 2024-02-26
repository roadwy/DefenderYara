
rule Backdoor_BAT_Bladabindi_GCE_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.GCE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_80_0 = {52 57 35 6a 63 6e 6c 77 64 47 46 6b 62 79 51 3d } //RW5jcnlwdGFkbyQ=  01 00 
		$a_01_1 = {63 63 38 31 37 64 36 32 61 34 32 31 61 66 66 31 36 34 33 62 64 63 36 30 65 31 33 35 33 63 62 62 32 } //01 00  cc817d62a421aff1643bdc60e1353cbb2
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_80_3 = {45 6e 63 72 79 70 74 61 64 6f 2e 65 78 65 } //Encryptado.exe  01 00 
		$a_01_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //00 00  CreateDecryptor
	condition:
		any of ($a_*)
 
}