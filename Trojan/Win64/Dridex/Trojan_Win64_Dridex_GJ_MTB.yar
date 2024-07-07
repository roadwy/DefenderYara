
rule Trojan_Win64_Dridex_GJ_MTB{
	meta:
		description = "Trojan:Win64/Dridex.GJ!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 c7 84 24 b8 00 00 00 e3 79 6c 78 49 89 c0 4d 01 c0 4c 89 84 24 d8 00 00 00 49 89 c0 49 81 c8 5b b8 6a 07 4c 89 84 24 d8 00 00 00 83 fa 06 } //1
		$a_01_1 = {3f 89 ea 39 b3 48 bf df 19 51 e6 f4 a6 34 75 a6 48 b3 05 bc 4b 25 9c ef e7 8f 97 e1 4a 37 08 64 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}