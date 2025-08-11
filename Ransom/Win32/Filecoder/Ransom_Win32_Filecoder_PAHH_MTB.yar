
rule Ransom_Win32_Filecoder_PAHH_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.PAHH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 47 56 73 62 47 38 73 49 47 46 73 62 43 42 35 62 33 56 79 49 47 5a 70 62 47 56 7a 49 47 68 68 64 6d 55 67 59 6d 56 6c 62 69 42 76 64 6d 56 79 64 33 4a 70 64 48 52 6c 62 69 34 67 55 32 56 75 5a 43 41 78 4d 44 41 6b 49 48 52 76 49 48 52 6f 61 58 4d 67 59 6e 52 6a 49 47 46 6b 5a 48 4a 6c 63 33 4d 67 4d 55 4e 4c 4f 45 4e 54 57 55 31 4e 62 56 4d 33 4f 55 64 58 4f 48 4a 74 4e 6e 64 51 55 56 4a 5a 63 7a 64 6c 53 47 68 53 64 6c 70 49 4e 43 42 30 62 79 42 79 5a 57 4e 76 64 6d 56 79 49 47 6c 30 4c 67 3d 3d } //5 SGVsbG8sIGFsbCB5b3VyIGZpbGVzIGhhdmUgYmVlbiBvdmVyd3JpdHRlbi4gU2VuZCAxMDAkIHRvIHRoaXMgYnRjIGFkZHJlc3MgMUNLOENTWU1NbVM3OUdXOHJtNndQUVJZczdlSGhSdlpINCB0byByZWNvdmVyIGl0Lg==
		$a_01_1 = {5c 44 65 73 6b 74 6f 70 5c 72 65 61 64 6d 65 2e 74 78 74 } //1 \Desktop\readme.txt
		$a_01_2 = {55 53 45 52 50 52 4f 46 49 4c 45 } //1 USERPROFILE
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}