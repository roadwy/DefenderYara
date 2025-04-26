
rule Ransom_Win32_MammonRansom_YAA_MTB{
	meta:
		description = "Ransom:Win32/MammonRansom.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {52 53 41 44 65 63 72 79 70 74 4b 65 79 5c 4b 45 59 2e 44 41 54 } //1 RSADecryptKey\KEY.DAT
		$a_01_1 = {52 53 41 44 65 63 72 79 70 74 4b 65 79 5c 50 75 62 6c 69 63 2e 74 78 74 } //1 RSADecryptKey\Public.txt
		$a_01_2 = {4d 61 6d 6d 6f 6e 5c 52 65 6c 65 61 73 65 5c 4d 61 6d 6d 6f 6e 2e 70 64 62 } //2 Mammon\Release\Mammon.pdb
		$a_01_3 = {4d 49 49 43 49 44 41 4e 42 67 6b 71 68 6b 69 47 39 77 30 42 41 51 45 46 41 41 4f 43 41 67 30 41 } //1 MIICIDANBgkqhkiG9w0BAQEFAAOCAg0A
		$a_01_4 = {2e 6c 6f 63 6b } //1 .lock
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}