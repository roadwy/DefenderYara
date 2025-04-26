
rule Trojan_BAT_RedLine_EM_MTB{
	meta:
		description = "Trojan:BAT/RedLine.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {25 16 1f 7c 9d 6f d7 00 00 0a 0d 16 13 04 2b 22 09 11 04 9a 13 05 06 11 05 6f 60 00 00 06 2c 0c 06 6f 5d 00 00 06 2c 04 17 0b 2b 0d 11 04 17 58 13 04 11 04 09 8e 69 32 d7 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_BAT_RedLine_EM_MTB_2{
	meta:
		description = "Trojan:BAT/RedLine.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {64 6e 6c 69 62 44 6f 74 4e 65 74 4c 69 6e 6b 65 64 52 65 73 6f 75 72 63 65 76 } //1 dnlibDotNetLinkedResourcev
		$a_81_1 = {6e 65 74 2e 74 63 70 3a 2f 2f } //1 net.tcp://
		$a_81_2 = {6c 6f 63 61 6c 68 6f 73 74 } //1 localhost
		$a_81_3 = {41 75 74 68 6f 72 69 7a 61 74 69 6f 6e } //1 Authorization
		$a_81_4 = {43 68 55 4d 42 79 55 31 4b 42 63 4a 4f 79 5a 43 4a 67 73 34 55 77 73 46 4b 6b 63 6e 4a 51 34 61 } //1 ChUMByU1KBcJOyZCJgs4UwsFKkcnJQ4a
		$a_81_5 = {4a 69 67 70 43 7a 41 32 48 6c 38 3d } //1 JigpCzA2Hl8=
		$a_81_6 = {44 6f 6f 72 6a 61 6d 62 } //1 Doorjamb
		$a_81_7 = {48 79 64 61 74 69 64 73 2e 65 78 65 } //1 Hydatids.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}