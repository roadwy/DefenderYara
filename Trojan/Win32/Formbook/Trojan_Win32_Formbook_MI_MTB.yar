
rule Trojan_Win32_Formbook_MI_MTB{
	meta:
		description = "Trojan:Win32/Formbook.MI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {68 74 74 70 3a 2f 2f 61 6c 6d 6f 6e 64 74 72 61 64 69 6e 67 6c 74 64 2e 63 6f 6d 2f 90 02 05 2e 65 78 65 90 00 } //1
		$a_01_1 = {46 45 41 52 4d 45 } //1 FEARME
		$a_01_2 = {4c 6f 56 45 4d 65 } //1 LoVEMe
		$a_01_3 = {4c 6f 63 6b 52 65 73 6f 75 72 63 65 } //1 LockResource
		$a_01_4 = {49 73 50 72 6f 63 65 73 73 6f 72 46 65 61 74 75 72 65 50 72 65 73 65 6e 74 } //1 IsProcessorFeaturePresent
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}