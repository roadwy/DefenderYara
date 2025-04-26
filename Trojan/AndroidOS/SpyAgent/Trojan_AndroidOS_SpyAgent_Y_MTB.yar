
rule Trojan_AndroidOS_SpyAgent_Y_MTB{
	meta:
		description = "Trojan:AndroidOS/SpyAgent.Y!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {49 4d 79 41 69 64 6c 49 6e 74 65 72 66 61 63 65 } //1 IMyAidlInterface
		$a_01_1 = {42 42 63 6f 6e 73 74 61 6e 74 59 59 } //1 BBconstantYY
		$a_01_2 = {2f 61 70 69 2f 75 70 6c 6f 61 64 2f 61 70 70 2d 69 63 6f 6e } //1 /api/upload/app-icon
		$a_01_3 = {6f 75 74 45 72 72 6f 72 2e 74 78 74 } //1 outError.txt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}