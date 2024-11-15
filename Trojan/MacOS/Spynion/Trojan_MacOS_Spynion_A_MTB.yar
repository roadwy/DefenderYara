
rule Trojan_MacOS_Spynion_A_MTB{
	meta:
		description = "Trojan:MacOS/Spynion.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {48 83 c3 f3 0f 84 a4 01 00 00 48 89 c7 be 20 00 00 00 48 89 da e8 dd c6 01 00 48 85 c0 0f 84 8b 01 00 00 48 8b 08 48 ba 20 2d 2d 72 65 61 6c 49 48 31 d1 48 8b 50 06 48 be 6c 49 6e 73 74 61 6c 6c 48 31 f2 48 09 ca 0f 84 4e 01 00 00 48 ff c0 4c 89 fb 48 29 c3 48 83 fb 0e 7d a4 } //1
		$a_00_1 = {49 83 c4 f3 0f 84 55 01 00 00 48 89 c7 be 20 00 00 00 4c 89 e2 e8 45 c6 01 00 48 85 c0 0f 84 3c 01 00 00 48 8b 08 4c 31 f9 48 8b 50 06 4c 31 f2 48 09 ca 74 14 48 ff c0 49 89 dc 49 29 c4 49 83 fc 0e 7d bc } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}