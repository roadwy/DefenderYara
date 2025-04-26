
rule Trojan_BAT_RecordBreaker_RDA_MTB{
	meta:
		description = "Trojan:BAT/RecordBreaker.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_01_0 = {6b 65 72 6e 65 6c 33 32 } //1 kernel32
		$a_01_1 = {4c 6f 61 64 4c 69 62 72 61 72 79 41 } //1 LoadLibraryA
		$a_01_2 = {47 65 74 50 72 6f 63 41 64 64 72 65 73 73 } //1 GetProcAddress
		$a_81_3 = {4f 72 61 63 6c 65 20 43 6f 72 70 6f 72 61 74 69 6f 6e } //1 Oracle Corporation
		$a_81_4 = {4a 61 76 61 20 50 6c 61 74 66 6f 72 6d 20 53 45 20 38 20 55 33 35 31 } //1 Java Platform SE 8 U351
		$a_01_5 = {11 07 07 03 07 91 09 61 d2 9c } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_01_5  & 1)*2) >=7
 
}