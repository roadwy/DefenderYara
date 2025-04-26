
rule Trojan_Win64_DuckTail_GA_MTB{
	meta:
		description = "Trojan:Win64/DuckTail.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {48 89 5d c8 44 89 75 d0 48 8d 4d c8 4c 8d 45 d8 ba 03 02 00 00 } //3
		$a_01_1 = {8b c6 8b 4d d8 88 4c 07 10 48 89 7d c0 } //2
		$a_01_2 = {48 89 5d c8 44 89 75 d0 48 8d 4d c8 } //1
		$a_01_3 = {44 6f 74 4e 65 74 52 75 6e 74 69 6d 65 44 65 62 75 67 48 65 61 64 65 72 } //1 DotNetRuntimeDebugHeader
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=7
 
}