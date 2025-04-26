
rule Trojan_Win64_Cobaltstrike_AUJ_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.AUJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {44 3a 5c 43 6f 62 61 6c 74 20 46 75 64 } //1 D:\Cobalt Fud
		$a_01_1 = {44 6f 63 75 6d 65 6e 74 73 5c 62 75 66 66 65 72 2e 74 78 74 } //1 Documents\buffer.txt
		$a_01_2 = {52 65 73 75 6c 74 20 6f 66 20 65 78 65 63 75 74 65 64 20 63 6f 64 65 } //1 Result of executed code
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}