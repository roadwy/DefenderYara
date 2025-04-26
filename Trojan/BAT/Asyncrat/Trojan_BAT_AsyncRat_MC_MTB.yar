
rule Trojan_BAT_AsyncRat_MC_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 0d 00 00 "
		
	strings :
		$a_80_0 = {42 45 35 34 35 32 35 32 2d 42 30 32 30 2d 34 42 45 46 2d 38 43 35 37 2d 35 41 43 45 35 41 46 37 36 33 32 45 } //BE545252-B020-4BEF-8C57-5ACE5AF7632E  1
		$a_80_1 = {44 75 63 6b 79 52 65 6c 6f 61 64 } //DuckyReload  1
		$a_80_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //FromBase64String  1
		$a_80_3 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //DebuggableAttribute  1
		$a_80_4 = {67 65 74 5f 4b 65 79 } //get_Key  1
		$a_80_5 = {42 43 72 79 70 74 44 65 73 74 72 6f 79 4b 65 79 } //BCryptDestroyKey  1
		$a_80_6 = {42 43 72 79 70 74 49 6d 70 6f 72 74 4b 65 79 } //BCryptImportKey  1
		$a_80_7 = {42 43 72 79 70 74 45 6e 63 72 79 70 74 } //BCryptEncrypt  1
		$a_80_8 = {52 65 70 6c 61 63 65 } //Replace  1
		$a_80_9 = {47 5a 69 70 53 74 72 65 61 6d } //GZipStream  1
		$a_80_10 = {54 6f 41 72 72 61 79 } //ToArray  1
		$a_80_11 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //MemoryStream  1
		$a_80_12 = {43 6f 6d 70 72 65 73 73 69 6f 6e 4d 6f 64 65 } //CompressionMode  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1+(#a_80_11  & 1)*1+(#a_80_12  & 1)*1) >=13
 
}