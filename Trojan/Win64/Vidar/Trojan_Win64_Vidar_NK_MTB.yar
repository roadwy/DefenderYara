
rule Trojan_Win64_Vidar_NK_MTB{
	meta:
		description = "Trojan:Win64/Vidar.NK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {48 8d 0c 40 48 c1 e1 04 48 8b 8c 0c 90 01 00 00 48 85 c9 74 e2 31 c9 e9 0e 02 00 00 } //2
		$a_01_1 = {48 8d 0c 40 48 c1 e1 04 48 8b 94 0c 00 01 00 00 48 8b 8c 0c f8 00 00 00 66 90 48 83 fa 09 75 17 } //1
		$a_01_2 = {49 6d 70 65 72 73 6f 6e 61 74 65 53 65 6c 66 } //1 ImpersonateSelf
		$a_01_3 = {72 65 6d 6f 74 65 72 65 6d 6f 74 65 } //1 remoteremote
		$a_01_4 = {47 6f 20 62 75 69 6c 64 } //1 Go build
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}