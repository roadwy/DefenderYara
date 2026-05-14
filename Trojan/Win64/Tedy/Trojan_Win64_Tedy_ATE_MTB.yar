
rule Trojan_Win64_Tedy_ATE_MTB{
	meta:
		description = "Trojan:Win64/Tedy.ATE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 0f b6 08 49 83 c0 01 31 d9 c1 eb 08 0f b6 c9 33 1c 8a 4c 39 c6 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win64_Tedy_ATE_MTB_2{
	meta:
		description = "Trojan:Win64/Tedy.ATE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 08 00 00 "
		
	strings :
		$a_01_0 = {65 00 7a 00 73 00 74 00 61 00 74 00 2e 00 72 00 75 00 } //5 ezstat.ru
		$a_01_1 = {4f 00 70 00 65 00 6e 00 69 00 6e 00 67 00 20 00 63 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 69 00 6f 00 6e 00 } //1 Opening connection
		$a_01_2 = {49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 69 00 6e 00 67 00 } //1 Installing
		$a_01_3 = {4c 00 6f 00 61 00 64 00 65 00 72 00 } //1 Loader
		$a_01_4 = {36 00 34 00 20 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 20 00 49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 65 00 72 00 } //1 64 Service Installer
		$a_01_5 = {43 00 61 00 6e 00 6e 00 6f 00 74 00 20 00 67 00 65 00 74 00 20 00 73 00 79 00 73 00 74 00 65 00 6d 00 20 00 64 00 69 00 72 00 65 00 63 00 74 00 6f 00 72 00 79 00 } //1 Cannot get system directory
		$a_01_6 = {4c 00 6f 00 61 00 64 00 65 00 72 00 20 00 6d 00 69 00 67 00 68 00 74 00 20 00 62 00 65 00 20 00 64 00 6f 00 77 00 6e 00 2c 00 20 00 63 00 68 00 65 00 63 00 6b 00 20 00 44 00 69 00 73 00 63 00 6f 00 72 00 64 00 } //1 Loader might be down, check Discord
		$a_01_7 = {50 00 61 00 79 00 6c 00 6f 00 61 00 64 00 20 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 65 00 64 00 } //1 Payload downloaded
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=12
 
}