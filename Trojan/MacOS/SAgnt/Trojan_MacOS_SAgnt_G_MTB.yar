
rule Trojan_MacOS_SAgnt_G_MTB{
	meta:
		description = "Trojan:MacOS/SAgnt.G!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {49 d3 e4 4c 89 e7 48 c1 ef 20 48 89 d0 31 d2 48 f7 f7 49 89 c1 48 89 d0 45 89 e2 45 89 c3 4c 89 ca 49 0f af d2 4c 0f a4 c0 20 48 39 d0 73 27 4c 01 e0 4c 39 e0 41 0f 93 c0 48 39 d0 41 0f 92 c7 31 db 45 20 c7 49 0f 45 dc 48 01 d8 41 0f b6 df 48 f7 d3 49 01 d9 } //1
		$a_01_1 = {48 29 d0 31 d2 48 f7 f7 4c 0f af d0 48 c1 e2 20 4c 09 da 4c 39 d2 73 25 4c 01 e2 4c 39 e2 41 0f 93 c0 4c 39 d2 0f 92 c3 31 ff 44 20 c3 49 0f 45 fc 48 01 fa 0f b6 fb 48 f7 d7 48 01 f8 4c 29 d2 49 c1 e1 20 49 09 c1 48 d3 ea } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}