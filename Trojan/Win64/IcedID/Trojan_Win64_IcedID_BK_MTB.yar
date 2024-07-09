
rule Trojan_Win64_IcedID_BK_MTB{
	meta:
		description = "Trojan:Win64/IcedID.BK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 6e 76 44 76 68 } //1 CnvDvh
		$a_01_1 = {4c 4b 67 6b 49 34 49 63 } //1 LKgkI4Ic
		$a_01_2 = {4d 41 53 30 77 58 36 30 54 44 36 } //1 MAS0wX60TD6
		$a_01_3 = {50 6c 75 67 69 6e 49 6e 69 74 } //1 PluginInit
		$a_01_4 = {59 77 49 6a 72 47 70 73 70 } //1 YwIjrGpsp
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win64_IcedID_BK_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.BK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {41 f7 ec c1 fa 04 8b c2 c1 e8 1f 03 d0 49 63 c4 41 83 c4 01 48 63 ca 48 6b c9 35 48 03 c8 48 8b 44 24 28 42 0f b6 8c 31 [0-04] 41 32 4c 00 ff 43 88 4c 18 ff 44 3b 64 24 20 72 } //4
		$a_01_1 = {36 3e 3e 72 73 45 45 6f 59 43 58 6b 32 24 4d 72 49 4c 73 76 52 24 57 51 79 54 55 36 46 6c 35 52 56 67 67 54 57 65 68 71 3e 23 53 31 } //1 6>>rsEEoYCXk2$MrILsvR$WQyTU6Fl5RVggTWehq>#S1
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}