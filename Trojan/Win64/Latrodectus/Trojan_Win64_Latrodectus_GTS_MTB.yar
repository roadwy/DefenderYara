
rule Trojan_Win64_Latrodectus_GTS_MTB{
	meta:
		description = "Trojan:Win64/Latrodectus.GTS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 02 00 00 "
		
	strings :
		$a_01_0 = {c5 fd 62 c3 c5 e5 6a dc c5 f5 ef c9 c5 e5 75 db c5 e5 71 f3 07 45 8a 34 11 c5 e5 67 db } //5
		$a_01_1 = {c5 dd 60 e1 c5 e5 60 dd c5 c5 73 d8 02 c5 fd 69 f4 c5 fd 61 c4 c5 dd 73 dc 02 c5 f5 73 db 02 c5 e5 69 d7 44 30 34 0f c5 e5 67 db c5 dd fd e6 } //4
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*4) >=9
 
}