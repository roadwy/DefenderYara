
rule Ransom_MSIL_Filecoder_EE_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.EE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {53 65 6c 65 63 74 20 2a 20 66 72 6f 6d 20 57 69 6e 33 32 5f 43 6f 6d 70 75 74 65 72 53 79 73 74 65 6d } //1 Select * from Win32_ComputerSystem
		$a_81_1 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 57 69 6e 33 32 5f 4e 65 74 77 6f 72 6b 41 64 61 70 74 65 72 43 6f 6e 66 69 67 75 72 61 74 69 6f 6e } //1 SELECT * FROM Win32_NetworkAdapterConfiguration
		$a_81_2 = {48 4f 57 5f 54 4f 5f 44 45 43 59 50 48 45 52 5f 46 49 4c 45 53 } //1 HOW_TO_DECYPHER_FILES
		$a_81_3 = {2e 6c 6f 63 6b 65 64 } //1 .locked
		$a_81_4 = {54 6e 56 74 59 6d 56 79 49 47 39 6d 49 47 5a 70 62 47 56 7a 49 47 56 75 59 33 4a 35 63 48 52 6c 5a 44 6f 67 } //1 TnVtYmVyIG9mIGZpbGVzIGVuY3J5cHRlZDog
		$a_81_5 = {55 47 39 7a 63 32 6c 69 62 47 55 67 59 57 5a 6d 5a 57 4e 30 5a 57 51 67 5a 6d 6c 73 5a 58 4d 36 49 41 } //1 UG9zc2libGUgYWZmZWN0ZWQgZmlsZXM6IA
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}