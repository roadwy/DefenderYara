
rule TrojanDownloader_O97M_Obfuse_JAB_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.JAB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {61 48 52 30 63 44 6f 76 4c 32 39 75 5a 57 52 79 61 58 5a 6c 4c 6d 78 70 64 6d 55 75 59 32 39 74 4c 32 52 76 64 32 35 73 62 32 46 6b 50 32 4e 70 5a 44 30 78 4f 44 55 33 4f 54 6b 31 4d 30 59 79 4e 44 4e 45 4f 54 63 35 4a 6e 4a 6c 63 32 6c 6b 50 54 45 34 4e 54 63 35 4f 54 55 7a 52 6a 49 30 4d 30 51 35 4e 7a 6b 6c 4d 6a 45 78 4d 6a 59 6d 59 58 56 30 61 47 74 6c 65 54 31 42 53 58 56 51 4d 48 67 74 65 54 45 33 64 6c 64 5a 64 31 55 3d } //1 aHR0cDovL29uZWRyaXZlLmxpdmUuY29tL2Rvd25sb2FkP2NpZD0xODU3OTk1M0YyNDNEOTc5JnJlc2lkPTE4NTc5OTUzRjI0M0Q5NzklMjExMjYmYXV0aGtleT1BSXVQMHgteTE3dldZd1U=
		$a_00_1 = {63 47 39 33 5a 58 4a 7a 61 47 56 73 62 43 35 6c 65 47 55 67 4c 57 56 34 5a 57 4e 31 64 47 6c 76 62 6e 42 76 62 47 6c 6a 65 53 42 69 65 58 42 68 63 33 4d 67 4c 56 63 67 53 47 6c 6b 5a 47 56 75 49 43 31 6a 62 32 31 74 59 57 35 6b 49 43 68 75 5a 58 63 74 62 32 4a 71 5a 57 4e 30 49 46 4e 35 63 33 52 6c 62 53 35 4f 5a 58 51 75 56 32 56 69 51 32 78 70 5a 57 35 30 4b 53 35 45 62 33 64 75 62 47 39 68 5a 45 5a 70 62 47 55 6f 4a 77 3d 3d } //1 cG93ZXJzaGVsbC5leGUgLWV4ZWN1dGlvbnBvbGljeSBieXBhc3MgLVcgSGlkZGVuIC1jb21tYW5kIChuZXctb2JqZWN0IFN5c3RlbS5OZXQuV2ViQ2xpZW50KS5Eb3dubG9hZEZpbGUoJw==
		$a_00_2 = {4a 79 77 6b 5a 57 35 32 4f 6c 52 6c 62 58 41 72 4a 31 78 7a 64 6d 4e 6f 62 33 4e 30 4c 6d 56 34 5a 53 63 70 4f 79 68 4f 5a 58 63 74 54 32 4a 71 5a 57 4e 30 49 43 31 6a 62 32 30 67 55 32 68 6c 62 47 77 75 51 58 42 77 62 47 6c 6a 59 58 52 70 62 32 34 70 4c 6c 4e 6f 5a 57 78 73 52 58 68 6c 59 33 56 30 5a 53 67 6b 5a 57 35 32 4f 6c 52 6c 62 58 41 72 4a 31 78 7a 64 6d 4e 6f 62 33 4e 30 4c 6d 56 34 5a 53 63 70 } //1 JywkZW52OlRlbXArJ1xzdmNob3N0LmV4ZScpOyhOZXctT2JqZWN0IC1jb20gU2hlbGwuQXBwbGljYXRpb24pLlNoZWxsRXhlY3V0ZSgkZW52OlRlbXArJ1xzdmNob3N0LmV4ZScp
		$a_03_3 = {4d 69 64 24 28 [0-64] 2c 20 [0-64] 2c 20 32 29 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}