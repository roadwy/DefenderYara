
rule Trojan_AndroidOS_SAgnt_BG_MTB{
	meta:
		description = "Trojan:AndroidOS/SAgnt.BG!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 65 6e 64 50 68 6f 6e 65 49 6e 66 6f 72 6d 61 74 69 6f 6e 41 6c 61 72 6d } //1 SendPhoneInformationAlarm
		$a_01_1 = {46 49 4e 44 20 53 4d 53 20 4c 4f 47 20 43 4f 4e 44 49 54 49 4f 4e 3d } //1 FIND SMS LOG CONDITION=
		$a_01_2 = {53 65 6e 64 50 68 6f 6e 65 54 69 6d 65 44 69 66 66 41 6c 61 72 6d } //1 SendPhoneTimeDiffAlarm
		$a_01_3 = {4d 61 73 6b 41 63 74 69 76 69 74 79 } //1 MaskActivity
		$a_01_4 = {72 65 70 6c 79 73 65 6e 64 73 6d 73 69 6e 66 6f } //1 replysendsmsinfo
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}