
rule Trojan_Win64_IcedID_DH_MTB{
	meta:
		description = "Trojan:Win64/IcedID.DH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0b 00 00 "
		
	strings :
		$a_01_0 = {50 6c 75 67 69 6e 49 6e 69 74 } //10 PluginInit
		$a_01_1 = {48 69 61 46 37 4f 2e 64 6c 6c } //1 HiaF7O.dll
		$a_01_2 = {41 4e 69 6a 68 48 44 56 } //1 ANijhHDV
		$a_01_3 = {42 56 49 6a 4b 4d 44 55 } //1 BVIjKMDU
		$a_01_4 = {43 66 5a 52 51 4d 4f 45 4b 4a } //1 CfZRQMOEKJ
		$a_01_5 = {44 54 54 4e 57 58 48 63 70 44 } //1 DTTNWXHcpD
		$a_01_6 = {5a 70 47 44 53 41 4c 63 56 6e 2e 64 6c 6c } //1 ZpGDSALcVn.dll
		$a_01_7 = {46 64 67 54 55 57 4c 4d 48 } //1 FdgTUWLMH
		$a_01_8 = {4a 6b 6e 70 6a 46 74 58 77 } //1 JknpjFtXw
		$a_01_9 = {4d 64 77 74 6d 77 71 54 61 58 } //1 MdwtmwqTaX
		$a_01_10 = {64 69 54 67 75 78 5a 79 52 45 55 } //1 diTguxZyREU
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=15
 
}