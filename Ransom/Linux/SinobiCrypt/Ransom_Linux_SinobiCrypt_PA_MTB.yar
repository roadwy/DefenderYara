
rule Ransom_Linux_SinobiCrypt_PA_MTB{
	meta:
		description = "Ransom:Linux/SinobiCrypt.PA!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {52 32 39 76 5a 43 42 68 5a 6e 52 6c 63 6d 35 76 62 32 34 73 49 48 64 6c 49 47 46 79 5a 53 42 54 61 57 35 76 59 6d 6b 67 52 33 4a 76 64 58 41 75 44 51 } //4 R29vZCBhZnRlcm5vb24sIHdlIGFyZSBTaW5vYmkgR3JvdXAuDQ
		$a_01_1 = {2f 52 45 41 44 4d 45 2e 74 78 74 } //1 /README.txt
		$a_01_2 = {46 6f 72 63 65 20 73 74 6f 70 20 61 6c 6c 20 45 53 58 69 20 56 4d 73 } //1 Force stop all ESXi VMs
		$a_01_3 = {45 6e 63 72 79 70 74 20 6f 6e 6c 79 20 73 70 65 63 69 66 69 65 64 20 66 69 6c 65 28 73 29 } //1 Encrypt only specified file(s)
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}