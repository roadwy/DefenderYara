
rule Trojan_BAT_SnakeKeyLogger_RDC_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {64 30 35 63 61 65 65 61 2d 31 39 62 65 2d 34 61 34 61 2d 38 37 30 35 2d 33 39 35 62 35 32 64 37 64 34 34 36 } //1 d05caeea-19be-4a4a-8705-395b52d7d446
		$a_01_1 = {6b 65 72 6e 65 6c 33 32 } //1 kernel32
		$a_01_2 = {47 65 74 50 72 6f 63 41 64 64 72 65 73 73 } //1 GetProcAddress
		$a_01_3 = {4c 6f 61 64 4c 69 62 72 61 72 79 } //1 LoadLibrary
		$a_01_4 = {45 62 6f 6f 6b 5f 4f 72 64 65 72 69 6e 67 } //1 Ebook_Ordering
		$a_01_5 = {4f 4b 4d 4c 50 4f 4b 4d } //1 OKMLPOKM
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}