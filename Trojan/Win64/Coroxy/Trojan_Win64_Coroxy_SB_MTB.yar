
rule Trojan_Win64_Coroxy_SB_MTB{
	meta:
		description = "Trojan:Win64/Coroxy.SB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {14 6d 94 03 50 90 01 01 a2 90 01 08 3b 82 90 01 04 12 05 90 01 04 64 48 e1 90 01 02 28 7a 90 01 01 66 32 6a 90 00 } //1
		$a_01_1 = {1b 3f 33 1e fb 9c 95 09 d2 12 d3 bc } //1
		$a_03_2 = {87 d7 2a e5 d0 69 90 01 01 bc 90 01 04 25 90 01 04 79 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}