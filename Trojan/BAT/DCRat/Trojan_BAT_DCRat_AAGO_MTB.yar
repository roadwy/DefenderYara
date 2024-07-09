
rule Trojan_BAT_DCRat_AAGO_MTB{
	meta:
		description = "Trojan:BAT/DCRat.AAGO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_03_0 = {06 20 00 01 00 00 6f ?? 00 00 0a 06 20 80 00 00 00 6f ?? 00 00 0a 06 18 6f ?? 00 00 0a 06 17 6f ?? 00 00 0a 06 03 6f ?? 00 00 0a 06 04 6f ?? 00 00 0a 06 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 0b 02 07 28 ?? 00 00 06 0c de 14 07 2c 06 07 6f ?? 00 00 0a dc } //4
		$a_01_1 = {66 00 52 00 5a 00 73 00 74 00 67 00 56 00 6f 00 6e 00 6b 00 6c 00 57 00 70 00 53 00 4c 00 65 00 62 00 39 00 5a 00 4b 00 63 00 6f 00 44 00 6b 00 47 00 50 00 7a 00 48 00 77 00 44 00 71 00 53 00 41 00 4d 00 79 00 54 00 78 00 6f 00 6f 00 70 00 47 00 63 00 62 00 3d 00 } //1 fRZstgVonklWpSLeb9ZKcoDkGPzHwDqSAMyTxoopGcb=
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=7
 
}