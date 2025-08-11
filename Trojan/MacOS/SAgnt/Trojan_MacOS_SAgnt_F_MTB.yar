
rule Trojan_MacOS_SAgnt_F_MTB{
	meta:
		description = "Trojan:MacOS/SAgnt.F!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8b 7d d8 4c 39 ff 0f 8d 53 01 00 00 45 31 f6 48 89 f8 31 db 48 85 ff 0f 88 37 01 00 00 41 8a 4c 04 08 8d 51 d0 80 fa 0a 73 4d 0f b6 c9 89 da 48 c1 eb 20 48 01 d2 48 8d 14 92 89 d6 48 c1 ea 20 48 8d 1c 9b 48 8d 14 5a 48 89 d3 48 c1 eb 20 48 c1 e2 20 48 09 f2 4d 01 f6 4f 8d 34 b6 48 83 c1 d0 48 01 d1 49 11 de 48 89 cb 48 ff c0 49 39 c7 } //1
		$a_01_1 = {49 d3 e2 4c 89 d7 48 c1 ef 20 48 89 f0 31 d2 48 f7 f7 49 89 c1 48 89 d0 45 89 d7 45 89 c3 4c 89 ca 49 0f af d7 4c 0f a4 c0 20 48 39 d0 73 25 4c 01 d0 4c 39 d0 41 0f 93 c0 48 39 d0 0f 92 c3 31 f6 44 20 c3 49 0f 45 f2 48 01 f0 0f b6 f3 48 f7 d6 49 01 f1 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}