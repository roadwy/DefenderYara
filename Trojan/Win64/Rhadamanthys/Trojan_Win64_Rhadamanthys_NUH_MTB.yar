
rule Trojan_Win64_Rhadamanthys_NUH_MTB{
	meta:
		description = "Trojan:Win64/Rhadamanthys.NUH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 8d 45 01 41 0f af c5 0f af 05 08 e9 0f 00 41 89 c0 41 c1 e8 1f 41 01 c0 41 d1 f8 48 8d 15 b8 e2 0e 00 b9 1b 00 00 00 41 b9 6a c6 00 00 } //2
		$a_01_1 = {8b 4c 24 3c 48 c1 e1 20 89 c2 48 09 ca 48 89 16 31 db 83 f8 ff } //1
		$a_01_2 = {41 80 f1 2a 0f b6 51 03 41 89 d2 41 80 f2 2f b8 04 00 00 00 45 08 ca } //1
		$a_01_3 = {80 f2 2a 44 0f b6 0c 01 45 89 ca 41 80 f2 2f 48 ff c0 41 08 d2 44 89 ca } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}