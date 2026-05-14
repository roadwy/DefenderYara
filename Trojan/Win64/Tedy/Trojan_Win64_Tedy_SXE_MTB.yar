
rule Trojan_Win64_Tedy_SXE_MTB{
	meta:
		description = "Trojan:Win64/Tedy.SXE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 02 00 00 "
		
	strings :
		$a_03_0 = {42 0f 10 14 00 0f 57 d0 f3 42 0f 6f 5c 00 ?? 66 0f ef d9 42 0f 11 14 00 f3 42 0f 7f 5c 00 ?? 49 83 c0 ?? 4c 39 c2 75 d8 } //15
		$a_03_1 = {66 41 0f 7e ca 44 89 d6 41 c1 ea ?? 45 32 14 08 c1 ee ?? 4d 8d 48 ?? 41 bb ?? ?? ?? ?? 49 83 f9 } //10
	condition:
		((#a_03_0  & 1)*15+(#a_03_1  & 1)*10) >=25
 
}