
rule Trojan_Win64_Tedy_GPB_MTB{
	meta:
		description = "Trojan:Win64/Tedy.GPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {49 89 d8 4c 89 f2 48 89 f9 48 83 c7 02 e8 7e ff ff ff 48 89 f0 31 d2 48 83 c6 01 48 f7 f5 41 0f b6 04 14 30 03 48 83 c3 01 49 39 f5 75 d2 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}