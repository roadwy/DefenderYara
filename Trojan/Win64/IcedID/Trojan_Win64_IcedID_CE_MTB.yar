
rule Trojan_Win64_IcedID_CE_MTB{
	meta:
		description = "Trojan:Win64/IcedID.CE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 "
		
	strings :
		$a_01_0 = {65 61 6e 69 73 68 5f 49 53 4f 5f 38 38 35 39 5f 31 5f 63 72 65 61 74 65 5f 65 6e 76 } //1 eanish_ISO_8859_1_create_env
		$a_01_1 = {65 67 5f 6d 61 67 69 63 5f 66 75 6e 63 } //1 eg_magic_func
		$a_01_2 = {49 59 52 67 45 56 51 6d 45 46 68 53 4d 51 58 53 4d 6f 75 4a } //1 IYRgEVQmEFhSMQXSMouJ
		$a_01_3 = {4b 59 53 73 4a 6e 4c 58 4e 7a 6e 73 4f 52 55 4c 72 54 6f 65 53 56 45 } //1 KYSsJnLXNznsORULrToeSVE
		$a_01_4 = {65 61 6e 69 73 68 5f 49 53 4f 5f 38 38 35 39 5f 31 5f 73 74 65 6d } //1 eanish_ISO_8859_1_stem
		$a_01_5 = {65 72 65 6e 63 68 5f 55 54 46 5f 38 5f 63 72 65 61 74 65 5f 65 6e 76 } //1 erench_UTF_8_create_env
		$a_01_6 = {65 75 74 5f 67 72 6f 75 70 69 6e 67 5f 62 5f 55 } //1 eut_grouping_b_U
		$a_01_7 = {65 67 5f 66 69 6e 66 6f 5f 64 73 6e 6f 77 62 61 6c 6c 5f 69 6e 69 74 } //1 eg_finfo_dsnowball_init
		$a_01_8 = {65 77 65 64 69 73 68 5f 49 53 4f 5f 38 38 35 39 5f 31 5f 73 74 65 6d } //1 ewedish_ISO_8859_1_stem
		$a_01_9 = {65 77 65 64 69 73 68 5f 55 54 46 5f 38 5f 73 74 65 6d } //1 ewedish_UTF_8_stem
		$a_01_10 = {4c 41 62 6f 67 4a 7a 50 4c 6b 73 55 51 63 57 58 } //1 LAbogJzPLksUQcWX
		$a_01_11 = {65 69 6e 64 5f 61 6d 6f 6e 67 5f 62 } //1 eind_among_b
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1) >=12
 
}