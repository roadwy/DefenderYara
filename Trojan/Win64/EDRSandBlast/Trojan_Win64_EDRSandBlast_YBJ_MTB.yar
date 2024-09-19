
rule Trojan_Win64_EDRSandBlast_YBJ_MTB{
	meta:
		description = "Trojan:Win64/EDRSandBlast.YBJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b7 d0 4d 8d 49 02 66 83 e8 61 66 83 f8 19 8d 4a 20 0f 47 d1 69 c2 93 01 00 01 44 33 c0 41 0f b7 01 66 85 c0 } //1
		$a_01_1 = {b9 01 00 00 00 ff 15 71 fc 01 00 ff c3 83 fb ff 72 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}