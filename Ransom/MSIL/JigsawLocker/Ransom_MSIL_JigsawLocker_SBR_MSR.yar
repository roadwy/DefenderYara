
rule Ransom_MSIL_JigsawLocker_SBR_MSR{
	meta:
		description = "Ransom:MSIL/JigsawLocker.SBR!MSR,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {52 61 6e 73 6f 6d 77 61 72 65 2e 4a 69 67 73 61 77 5c 6f 62 6a 5c 78 38 36 5c 44 65 62 75 67 5c 43 6f 6e 73 6f 6c 65 41 70 70 6c 69 63 61 74 69 6f 6e 2e 70 64 62 } //1 Ransomware.Jigsaw\obj\x86\Debug\ConsoleApplication.pdb
		$a_01_1 = {45 00 78 00 74 00 65 00 6e 00 73 00 69 00 6f 00 6e 00 73 00 54 00 6f 00 45 00 6e 00 63 00 72 00 79 00 70 00 74 00 } //1 ExtensionsToEncrypt
		$a_01_2 = {57 00 57 00 39 00 31 00 63 00 69 00 42 00 77 00 5a 00 58 00 4a 00 7a 00 62 00 32 00 35 00 68 00 62 00 43 00 42 00 6d 00 61 00 57 00 78 00 6c 00 63 00 79 00 42 00 68 00 63 00 6d 00 55 00 67 00 59 00 6d 00 56 00 70 00 62 00 6d 00 63 00 67 00 5a 00 47 00 56 00 73 00 5a 00 58 00 52 00 6c 00 5a 00 } //1 WW91ciBwZXJzb25hbCBmaWxlcyBhcmUgYmVpbmcgZGVsZXRlZ
		$a_01_3 = {5a 00 57 00 35 00 6a 00 63 00 6e 00 6c 00 77 00 64 00 47 00 56 00 6b 00 49 00 48 00 6c 00 76 00 64 00 58 00 49 00 67 00 63 00 47 00 56 00 79 00 63 00 32 00 39 00 75 00 59 00 57 00 77 00 67 00 5a 00 6d 00 6c 00 73 00 5a 00 58 00 4d 00 } //1 ZW5jcnlwdGVkIHlvdXIgcGVyc29uYWwgZmlsZXM
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}