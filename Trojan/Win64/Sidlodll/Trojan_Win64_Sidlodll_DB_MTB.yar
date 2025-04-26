
rule Trojan_Win64_Sidlodll_DB_MTB{
	meta:
		description = "Trojan:Win64/Sidlodll.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 06 00 00 "
		
	strings :
		$a_80_0 = {52 75 6e 53 68 65 6c 6c 63 6f 64 65 50 72 6f 63 28 29 } //RunShellcodeProc()  10
		$a_80_1 = {52 65 61 64 50 61 79 6c 6f 61 64 46 72 6f 6d 44 69 73 63 28 29 } //ReadPayloadFromDisc()  10
		$a_80_2 = {6c 6f 67 67 65 72 5f 69 6e 69 74 28 29 } //logger_init()  1
		$a_80_3 = {43 6c 69 65 6e 74 20 68 6f 6f 6b } //Client hook  1
		$a_80_4 = {63 3a 5c 64 65 62 75 67 5f 6c 6f 67 5c } //c:\debug_log\  1
		$a_80_5 = {72 63 34 4b 65 79 } //rc4Key  1
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*10+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=24
 
}