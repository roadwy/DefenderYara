
rule Trojan_Win64_ClawHugsLoader_C_dha{
	meta:
		description = "Trojan:Win64/ClawHugsLoader.C!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_01_0 = {00 74 5f 6c 6f 61 64 65 72 2e 64 6c 6c 00 } //1
		$a_01_1 = {00 62 5f 6c 6f 61 64 65 72 5f 6c 6f 63 61 6c 5f 64 6c 6c 2e 64 6c 6c 00 } //1
		$a_01_2 = {00 62 5f 6c 6f 61 64 65 72 5f 6c 6f 63 61 6c 5f 62 69 6e 64 65 72 2e 64 6c 6c 00 } //1
		$a_01_3 = {00 52 75 6e 64 6c 6c 33 32 45 6e 74 72 79 00 53 65 72 76 69 63 65 4d 61 69 6e 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=1
 
}