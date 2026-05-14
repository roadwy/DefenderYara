
rule Trojan_BAT_QuasarRat_RVA_MTB{
	meta:
		description = "Trojan:BAT/QuasarRat.RVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {57 d5 02 28 09 0a 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 5a 00 00 00 12 00 00 00 24 00 00 00 c9 8b 00 00 5f 00 00 00 9b 00 00 00 18 00 00 00 01 00 00 00 06 00 00 00 17 00 00 00 05 00 00 00 06 00 00 00 01 00 00 00 05 00 00 00 0f 00 00 00 09 } //1
		$a_81_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_81_2 = {4d 66 52 75 6e 6e 65 72 2e 65 78 65 } //1 MfRunner.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}