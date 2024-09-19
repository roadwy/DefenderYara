
rule Trojan_BAT_DCRat_NB_MTB{
	meta:
		description = "Trojan:BAT/DCRat.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_01_0 = {02 03 02 4b 03 04 61 05 61 58 0e 07 0e 04 e0 95 58 7e 82 04 00 04 0e 06 17 59 e0 95 58 0e 05 28 bf 11 00 06 58 54 2a } //5
		$a_81_1 = {52 53 41 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //1 RSACryptoServiceProvider
		$a_81_2 = {73 65 74 5f 55 73 65 4d 61 63 68 69 6e 65 4b 65 79 53 74 6f 72 65 } //1 set_UseMachineKeyStore
		$a_81_3 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //1 RijndaelManaged
		$a_81_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_01_0  & 1)*5+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=9
 
}