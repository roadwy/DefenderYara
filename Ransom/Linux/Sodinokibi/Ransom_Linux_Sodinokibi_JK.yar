
rule Ransom_Linux_Sodinokibi_JK{
	meta:
		description = "Ransom:Linux/Sodinokibi.JK,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 45 fc c1 e0 02 48 63 d0 48 8b 45 a8 48 01 c2 8b 45 fc 48 98 8b 44 85 b0 88 02 8b 45 fc c1 e0 02 48 98 48 8d 50 01 48 8b 45 a8 48 01 c2 8b 45 fc 48 98 8b 44 85 b0 c1 e8 08 88 02 8b 45 fc c1 e0 02 48 98 48 8d 50 02 48 8b 45 a8 48 01 c2 8b 45 fc 48 98 8b 44 85 b0 c1 e8 10 88 02 8b 45 fc c1 e0 02 48 98 48 8d 50 03 48 8b 45 a8 48 01 c2 8b 45 fc 48 98 8b 44 85 b0 c1 e8 18 88 02 83 45 fc 01 } //1
		$a_01_1 = {4c 53 30 74 50 54 30 39 49 46 64 6c 62 47 4e 76 62 57 55 75 49 45 46 6e 59 57 6c 75 4c 69 41 39 50 54 30 74 4c 53 30 4b 43 6c 73 72 58 53 42 58 61 47 46 30 63 79 42 49 59 58 42 77 5a 57 34 } //1 LS0tPT09IFdlbGNvbWUuIEFnYWluLiA9PT0tLS0KClsrXSBXaGF0cyBIYXBwZW4
		$a_00_2 = {53 65 63 75 72 65 56 69 73 6f 72 } //65436 SecureVisor
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*65436) >=2
 
}