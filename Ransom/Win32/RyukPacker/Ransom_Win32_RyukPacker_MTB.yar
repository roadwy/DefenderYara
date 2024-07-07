
rule Ransom_Win32_RyukPacker_MTB{
	meta:
		description = "Ransom:Win32/RyukPacker!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_01_0 = {46 75 63 6b 20 44 65 66 } //1 Fuck Def
		$a_01_1 = {43 4c 53 49 44 5c 25 31 5c 49 6e 70 72 6f 63 48 61 6e 64 6c 65 72 33 32 } //1 CLSID\%1\InprocHandler32
		$a_01_2 = {43 4c 53 49 44 5c 25 31 5c 4c 6f 63 61 6c 53 65 72 76 65 72 33 32 } //1 CLSID\%1\LocalServer32
		$a_01_3 = {25 32 5c 70 72 6f 74 6f 63 6f 6c 5c 53 74 64 46 69 6c 65 45 64 69 74 69 6e 67 5c 73 65 72 76 65 72 } //1 %2\protocol\StdFileEditing\server
		$a_01_4 = {5b 6f 70 65 6e 28 22 25 31 22 29 5d } //1 [open("%1")]
		$a_01_5 = {64 64 65 65 78 65 63 } //1 ddeexec
		$a_01_6 = {4e 65 74 51 75 65 72 79 44 69 73 70 6c 61 79 49 6e 66 6f 72 6d 61 74 69 6f 6e } //1 NetQueryDisplayInformation
		$a_01_7 = {43 72 79 70 74 45 6e 63 72 79 70 74 } //1 CryptEncrypt
		$a_01_8 = {43 72 79 70 74 49 6d 70 6f 72 74 4b 65 79 } //1 CryptImportKey
		$a_01_9 = {43 72 79 70 74 41 63 71 75 69 72 65 43 6f 6e 74 65 78 74 57 } //1 CryptAcquireContextW
		$a_01_10 = {47 00 65 00 74 00 55 00 73 00 65 00 72 00 4e 00 61 00 6d 00 65 00 73 00 } //1 GetUserNames
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=11
 
}