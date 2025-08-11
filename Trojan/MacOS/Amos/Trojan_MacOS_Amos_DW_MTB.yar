
rule Trojan_MacOS_Amos_DW_MTB{
	meta:
		description = "Trojan:MacOS/Amos.DW!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 83 fb f8 73 50 48 89 d8 48 83 e0 f8 48 83 c0 08 49 89 dc 49 83 cc 07 49 83 fc 17 4c 0f 44 e0 49 ff c4 4c 89 e7 e8 a2 1d 00 00 49 89 47 10 49 83 cc 01 4d 89 27 49 89 5f 08 49 89 c7 } //1
		$a_01_1 = {4c 89 f0 48 83 e0 f8 48 83 c0 08 4d 89 f7 49 83 cf 07 49 83 ff 17 4c 0f 44 f8 49 ff c7 4c 89 ff e8 bb 0e 00 00 49 83 cf 01 4c 89 3b 48 89 43 10 4c 89 73 08 48 83 c4 08 5b 41 5e 41 5f 5d } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}