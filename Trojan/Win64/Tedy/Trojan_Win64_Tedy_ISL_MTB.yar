
rule Trojan_Win64_Tedy_ISL_MTB{
	meta:
		description = "Trojan:Win64/Tedy.ISL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8b c1 49 f7 f2 42 0f b6 04 1a 41 30 04 09 48 ff c1 49 3b c8 72 e7 } //5
		$a_01_1 = {0f b6 04 0a 41 32 04 08 88 01 48 8d 49 01 48 83 ee 01 75 ec } //4
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*4) >=9
 
}