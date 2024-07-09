
rule Trojan_BAT_Small_CK_MTB{
	meta:
		description = "Trojan:BAT/Small.CK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 06 00 00 "
		
	strings :
		$a_03_0 = {2d 25 1f 10 d0 [0-04] 28 [0-04] d0 [0-04] 28 [0-04] 28 [0-04] 28 [0-04] 80 [0-04] 7e [0-04] 7b [0-04] 7e [0-04] 18 8d [0-04] 25 16 12 02 28 [0-04] a2 25 17 07 a2 28 [0-0e] 26 08 17 58 0c 08 07 } //10
		$a_80_1 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //DownloadData  2
		$a_80_2 = {47 65 74 50 72 6f 63 41 64 64 72 65 73 73 } //GetProcAddress  2
		$a_80_3 = {41 64 64 72 65 73 73 4f 66 45 6e 74 72 79 50 6f 69 6e 74 } //AddressOfEntryPoint  2
		$a_80_4 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //FromBase64String  2
		$a_80_5 = {53 69 7a 65 4f 66 52 61 77 44 61 74 61 } //SizeOfRawData  2
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2+(#a_80_4  & 1)*2+(#a_80_5  & 1)*2) >=20
 
}