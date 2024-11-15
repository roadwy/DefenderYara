
rule Trojan_Win32_LummaStealz_DA_MTB{
	meta:
		description = "Trojan:Win32/LummaStealz.DA!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {02 0f b7 16 83 c6 02 66 85 d2 75 ef 66 c7 00 00 00 0f b7 11 } //1
		$a_01_1 = {0c 0f b7 4c 24 04 66 89 0f 83 c7 02 39 f7 73 0c 01 c3 39 eb } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}