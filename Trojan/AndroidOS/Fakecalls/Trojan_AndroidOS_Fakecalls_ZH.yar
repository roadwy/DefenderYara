
rule Trojan_AndroidOS_Fakecalls_ZH{
	meta:
		description = "Trojan:AndroidOS/Fakecalls.ZH,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6f 6e 43 61 6c 6c 52 65 6d 6f 76 65 64 3a 20 6e 75 6d 62 65 72 3d } //1 onCallRemoved: number=
		$a_01_1 = {64 65 6c 65 74 65 20 43 61 6c 6c 4c 6f 67 3a } //1 delete CallLog:
		$a_01_2 = {63 61 6c 6c 73 4c 69 73 74 } //1 callsList
		$a_01_3 = {62 6c 61 63 6b 4c 69 73 74 20 55 70 64 61 74 65 20 6e 75 6d 62 65 72 3a } //1 blackList Update number:
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}