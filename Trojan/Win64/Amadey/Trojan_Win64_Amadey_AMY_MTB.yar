
rule Trojan_Win64_Amadey_AMY_MTB{
	meta:
		description = "Trojan:Win64/Amadey.AMY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {31 c0 48 8d 7c 24 38 b9 1a 00 00 00 c7 44 24 30 70 00 00 00 f3 ab 48 8d 05 7b 8c 00 00 c7 44 24 60 05 00 00 00 48 8d 4c 24 30 48 89 44 24 40 48 8d 05 68 8c 00 00 48 89 44 24 48 48 8d 05 6b 8c 00 00 48 89 44 24 50 c7 44 24 34 40 } //2
		$a_01_1 = {53 74 6f 72 6d 44 4c 4c 5f 4d 75 74 65 78 31 32 33 } //1 StormDLL_Mutex123
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}