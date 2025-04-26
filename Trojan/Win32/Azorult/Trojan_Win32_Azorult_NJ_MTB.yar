
rule Trojan_Win32_Azorult_NJ_MTB{
	meta:
		description = "Trojan:Win32/Azorult.NJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_02_0 = {88 0c 02 8b 0d [0-04] 81 [0-05] 75 06 89 1d [0-04] 40 3b c1 90 18 8b 15 [0-04] 8a 8c 02 [0-04] 8b 15 } //1
		$a_81_1 = {53 79 73 74 65 6d 46 75 6e 63 74 69 6f 6e 30 33 36 } //1 SystemFunction036
		$a_81_2 = {47 41 49 73 50 72 6f 63 65 73 73 6f 72 46 65 61 74 75 72 65 50 72 65 73 65 6e 74 } //1 GAIsProcessorFeaturePresent
		$a_81_3 = {53 69 7a 65 6f 66 52 65 73 6f 75 72 63 65 } //1 SizeofResource
		$a_81_4 = {45 52 52 4f 52 44 49 41 4c 4f 47 } //1 ERRORDIALOG
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}