
rule Trojan_Win64_IcedID_MN_MTB{
	meta:
		description = "Trojan:Win64/IcedID.MN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_01_0 = {50 6c 75 67 69 6e 49 6e 69 74 } //10 PluginInit
		$a_01_1 = {67 69 4b 43 52 4f 2e 64 6c 6c } //1 giKCRO.dll
		$a_01_2 = {41 69 4e 42 78 42 50 44 57 44 } //1 AiNBxBPDWD
		$a_01_3 = {41 65 46 6a 69 78 68 6c } //1 AeFjixhl
		$a_01_4 = {57 57 73 52 45 4a 7a 6a } //1 WWsREJzj
		$a_01_5 = {43 56 4f 4c 58 55 44 6e } //1 CVOLXUDn
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=15
 
}
rule Trojan_Win64_IcedID_MN_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.MN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 05 00 00 "
		
	strings :
		$a_01_0 = {68 61 73 75 6e 79 66 67 75 61 73 66 6a 69 75 61 73 68 79 66 61 6a 73 75 66 69 61 6b } //10 hasunyfguasfjiuashyfajsufiak
		$a_01_1 = {63 79 75 73 64 62 61 73 68 62 79 64 67 61 75 73 6a 64 6b 61 73 64 75 6a 61 } //10 cyusdbashbydgausjdkasduja
		$a_01_2 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } //2 WaitForSingleObject
		$a_01_3 = {43 72 65 61 74 65 45 76 65 6e 74 57 } //2 CreateEventW
		$a_01_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //2 VirtualAlloc
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=16
 
}
rule Trojan_Win64_IcedID_MN_MTB_3{
	meta:
		description = "Trojan:Win64/IcedID.MN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {74 4f 56 45 52 5f 62 65 73 74 5f 64 65 73 74 72 6f 79 } //1 tOVER_best_destroy
		$a_01_1 = {74 4f 56 45 52 5f 62 65 73 74 5f 66 69 6e 69 73 68 } //1 tOVER_best_finish
		$a_01_2 = {74 4f 56 45 52 5f 63 68 65 63 6b 54 6f 74 61 6c 43 6f 6d 70 72 65 73 73 65 64 53 69 7a 65 } //1 tOVER_checkTotalCompressedSize
		$a_01_3 = {74 4f 56 45 52 5f 64 69 63 74 53 65 6c 65 63 74 69 6f 6e 45 72 72 6f 72 } //1 tOVER_dictSelectionError
		$a_01_4 = {74 4f 56 45 52 5f 73 65 6c 65 63 74 44 69 63 74 } //1 tOVER_selectDict
		$a_01_5 = {74 4f 56 45 52 5f 77 61 72 6e 4f 6e 53 6d 61 6c 6c 43 6f 72 70 75 73 } //1 tOVER_warnOnSmallCorpus
		$a_01_6 = {74 53 45 5f 62 75 69 6c 64 43 54 61 62 6c 65 5f 72 61 77 } //1 tSE_buildCTable_raw
		$a_01_7 = {74 53 45 5f 63 6f 6d 70 72 65 73 73 5f 75 73 69 6e 67 43 54 61 62 6c 65 } //1 tSE_compress_usingCTable
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}
rule Trojan_Win64_IcedID_MN_MTB_4{
	meta:
		description = "Trojan:Win64/IcedID.MN!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {f7 ea 8d 04 0a 89 c2 c1 fa 05 89 c8 c1 f8 1f 89 d3 29 c3 89 d8 6b c0 2d 89 ca 29 c2 89 d0 48 98 48 03 85 88 02 00 00 0f b6 00 44 31 c8 41 88 00 83 85 9c 02 00 00 01 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}