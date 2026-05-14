
rule Trojan_Win64_RedCap_LMA_MTB{
	meta:
		description = "Trojan:Win64/RedCap.LMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f 86 d9 00 00 00 55 48 89 e5 48 83 ec 40 66 44 0f d6 7c 24 38 c6 44 24 17 00 44 0f 11 7c 24 28 31 db 89 c1 b8 01 00 00 00 } //20
		$a_01_1 = {49 3b 66 10 0f 86 d9 00 00 00 55 48 89 e5 48 83 ec 40 66 44 0f d6 7c 24 38 c6 44 24 17 00 44 0f 11 7c 24 28 31 db 89 c1 b8 01 00 00 00 } //10
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}