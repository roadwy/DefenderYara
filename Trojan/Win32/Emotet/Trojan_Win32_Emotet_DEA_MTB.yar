
rule Trojan_Win32_Emotet_DEA_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {03 ca 81 e1 90 01 04 90 13 8b 44 24 90 01 01 8a 10 8a 4c 0c 90 01 01 32 d1 88 10 90 02 04 89 44 24 90 01 01 ff 4c 24 90 01 01 0f 85 90 00 } //1
		$a_81_1 = {36 47 52 56 75 4b 64 51 57 4f 67 71 5a 59 76 51 42 48 69 6f 55 39 38 34 37 } //1 6GRVuKdQWOgqZYvQBHioU9847
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}