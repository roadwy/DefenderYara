
rule Trojan_Win64_Stealer_NS_MTB{
	meta:
		description = "Trojan:Win64/Stealer.NS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {44 89 16 45 31 d2 4c 89 c6 49 89 d1 eb dc 0f b6 48 06 0f b7 40 04 35 65 b1 00 00 } //3
		$a_01_1 = {88 4a 06 66 89 42 04 4c 8d ac 24 f8 00 00 00 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}