
rule Trojan_BAT_ClipBanker_PA_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {49 6e 76 6f 6b 65 } //1 Invoke
		$a_01_1 = {44 65 63 72 79 70 } //1 Decryp
		$a_01_2 = {52 65 73 6f 6c 76 65 } //1 Resolve
		$a_01_3 = {45 6e 63 6f 64 69 6e 67 } //1 Encoding
		$a_01_4 = {44 65 63 6f 6d 70 72 65 73 73 } //1 Decompress
		$a_01_5 = {4c 7a 6d 61 44 65 63 6f 64 65 72 } //1 LzmaDecoder
		$a_01_6 = {4c 6f 61 64 4d 6f 64 75 6c 65 } //1 LoadModule
		$a_01_7 = {52 65 76 65 72 73 65 44 65 63 6f 64 65 } //1 ReverseDecode
		$a_01_8 = {24 34 31 37 34 35 30 61 66 2d 65 64 36 64 2d 34 31 37 37 2d 62 30 63 62 2d 63 65 66 34 63 63 64 62 64 62 30 32 } //1 $417450af-ed6d-4177-b0cb-cef4ccdbdb02
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}