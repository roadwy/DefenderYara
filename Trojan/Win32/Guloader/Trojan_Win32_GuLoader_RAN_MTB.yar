
rule Trojan_Win32_GuLoader_RAN_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {5c 75 6e 6e 69 67 67 61 72 64 5c 61 67 67 72 61 76 65 72 69 6e 67 65 6e 73 5c 61 62 65 74 74 6f 72 } //1 \unniggard\aggraveringens\abettor
		$a_81_1 = {76 65 72 70 61 20 62 65 64 6d 6d 65 6c 73 65 73 6b 6f 6d 69 74 65 65 6e 20 65 6d 69 67 72 65 72 65 6e 64 65 73 } //1 verpa bedmmelseskomiteen emigrerendes
		$a_81_2 = {73 61 63 63 61 67 65 20 6d 6f 72 61 6c 70 72 64 69 6b 65 6e 65 72 20 67 61 64 65 64 72 73 6e 67 6c 65 72 73 } //1 saccage moralprdikener gadedrsnglers
		$a_81_3 = {6d 61 67 69 6b 65 72 6e 65 73 2e 65 78 65 } //1 magikernes.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}