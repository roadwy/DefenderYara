
rule Trojan_Win64_DllHijack_GZT_MTB{
	meta:
		description = "Trojan:Win64/DllHijack.GZT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {4f b7 44 86 df 14 a2 5a 6a aa 00 2f 5b 33 f4 20 d1 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}
rule Trojan_Win64_DllHijack_GZT_MTB_2{
	meta:
		description = "Trojan:Win64/DllHijack.GZT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_01_0 = {5b 5d 9c 31 66 ab b6 2a 8b 64 ac 4a } //5
		$a_01_1 = {b0 02 6b 28 d4 2a 0e 31 d0 } //5
		$a_80_2 = {65 71 66 2e 64 6c 6c } //eqf.dll  1
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_80_2  & 1)*1) >=11
 
}