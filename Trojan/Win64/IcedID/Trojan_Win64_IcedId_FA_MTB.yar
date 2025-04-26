
rule Trojan_Win64_IcedId_FA_MTB{
	meta:
		description = "Trojan:Win64/IcedId.FA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {74 38 79 6f 6f 5a } //1 t8yooZ
		$a_01_1 = {76 4b 69 46 79 30 } //1 vKiFy0
		$a_01_2 = {77 78 6c 79 69 42 68 70 57 } //1 wxlyiBhpW
		$a_01_3 = {78 53 73 6b 4d 47 79 } //1 xSskMGy
		$a_01_4 = {79 67 61 73 62 66 67 74 66 68 6a 61 73 6b 66 79 61 73 } //1 ygasbfgtfhjaskfyas
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win64_IcedId_FA_MTB_2{
	meta:
		description = "Trojan:Win64/IcedId.FA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {68 77 51 69 52 4d 68 63 53 50 4e } //1 hwQiRMhcSPN
		$a_01_1 = {6d 32 6b 56 4b 59 46 42 4f 61 76 39 35 61 50 6c } //1 m2kVKYFBOav95aPl
		$a_01_2 = {6d 64 45 51 69 32 70 33 } //1 mdEQi2p3
		$a_01_3 = {6d 66 6c 64 4b 37 35 36 73 35 6c 39 4a 74 } //1 mfldK756s5l9Jt
		$a_01_4 = {6e 75 79 68 61 66 6a 73 68 79 67 66 61 73 66 6a 61 73 79 6a 61 73 } //1 nuyhafjshygfasfjasyjas
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win64_IcedId_FA_MTB_3{
	meta:
		description = "Trojan:Win64/IcedId.FA!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 8a 09 4d 8d 49 02 88 4c 24 30 8a 4c 24 30 83 e9 25 88 4c 24 30 8a 44 24 30 c0 e0 04 88 44 24 30 8a 44 24 30 88 44 24 38 41 8a 41 ff 88 44 24 30 8a 44 24 30 83 e8 38 88 44 24 30 0f b6 44 24 38 8a 4c 24 30 0b c8 88 4c 24 38 0f b6 44 24 38 8a 4c 24 40 33 c8 88 4c 24 38 8a 44 24 40 fe c0 88 44 24 40 8a 44 24 38 41 88 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}