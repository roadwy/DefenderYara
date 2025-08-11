
rule Trojan_Win32_SusKernelCallBackTable_AM{
	meta:
		description = "Trojan:Win32/SusKernelCallBackTable.AM,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {4b 65 72 6e 65 6c 43 61 6c 6c 62 61 63 6b 54 61 62 6c 65 00 } //1 敋湲汥慃汬慢正慔汢e
		$a_01_1 = {53 65 6e 64 4d 65 73 73 61 67 65 00 } //1 敓摮敍獳条e
		$a_01_2 = {66 6e 43 4f 50 59 44 41 54 41 00 } //1
		$a_01_3 = {6d 73 69 6e 66 6f 33 32 2e 65 78 65 00 } //1
		$a_00_4 = {61 00 61 00 30 00 36 00 65 00 33 00 36 00 65 00 2d 00 37 00 38 00 37 00 36 00 2d 00 34 00 62 00 61 00 33 00 2d 00 62 00 65 00 65 00 65 00 2d 00 34 00 32 00 62 00 64 00 38 00 30 00 66 00 66 00 33 00 36 00 32 00 6d 00 } //-1 aa06e36e-7876-4ba3-beee-42bd80ff362m
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*-1) >=4
 
}
rule Trojan_Win32_SusKernelCallBackTable_AM_2{
	meta:
		description = "Trojan:Win32/SusKernelCallBackTable.AM,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4b 65 72 6e 65 6c 43 61 6c 6c 62 61 63 6b 54 61 62 6c 65 00 } //1 敋湲汥慃汬慢正慔汢e
		$a_01_1 = {53 65 6e 64 4d 65 73 73 61 67 65 00 } //1 敓摮敍獳条e
		$a_01_2 = {66 6e 43 4f 50 59 44 41 54 41 00 } //1
		$a_01_3 = {6d 73 69 6e 66 6f 33 32 2e 65 78 65 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}