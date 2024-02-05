
rule Trojan_BAT_Small_CK_MTB{
	meta:
		description = "Trojan:BAT/Small.CK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 06 00 00 0a 00 "
		
	strings :
		$a_03_0 = {2d 25 1f 10 d0 90 02 04 28 90 02 04 d0 90 02 04 28 90 02 04 28 90 02 04 28 90 02 04 80 90 02 04 7e 90 02 04 7b 90 02 04 7e 90 02 04 18 8d 90 02 04 25 16 12 02 28 90 02 04 a2 25 17 07 a2 28 90 02 0e 26 08 17 58 0c 08 07 90 00 } //02 00 
		$a_80_1 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //DownloadData  02 00 
		$a_80_2 = {47 65 74 50 72 6f 63 41 64 64 72 65 73 73 } //GetProcAddress  02 00 
		$a_80_3 = {41 64 64 72 65 73 73 4f 66 45 6e 74 72 79 50 6f 69 6e 74 } //AddressOfEntryPoint  02 00 
		$a_80_4 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //FromBase64String  02 00 
		$a_80_5 = {53 69 7a 65 4f 66 52 61 77 44 61 74 61 } //SizeOfRawData  00 00 
	condition:
		any of ($a_*)
 
}