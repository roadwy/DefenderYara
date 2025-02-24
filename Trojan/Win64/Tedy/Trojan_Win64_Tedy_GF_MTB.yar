
rule Trojan_Win64_Tedy_GF_MTB{
	meta:
		description = "Trojan:Win64/Tedy.GF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 33 08 0f b6 40 08 34 1a 48 89 4c 24 50 88 44 24 58 48 8d 4c 24 30 48 8d 54 24 50 41 b8 09 00 00 00 } //1
		$a_01_1 = {65 78 65 63 75 74 65 5f 70 79 74 68 6f 6e 5f 65 6e 74 72 79 70 6f 69 6e 74 } //1 execute_python_entrypoint
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}