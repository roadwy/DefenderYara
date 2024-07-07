
rule Trojan_AndroidOS_SAgnt_AC_MTB{
	meta:
		description = "Trojan:AndroidOS/SAgnt.AC!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {74 69 6b 69 74 61 6b 61 2f 73 75 62 2f 4d 61 69 6e 41 63 74 69 76 69 74 79 } //1 tikitaka/sub/MainActivity
		$a_01_1 = {73 65 6e 73 6d 73 } //1 sensms
		$a_01_2 = {73 65 6e 64 54 65 78 74 4d 65 73 73 61 67 65 } //1 sendTextMessage
		$a_01_3 = {2f 61 70 69 2f 6b 65 79 77 6f 72 64 73 2d 69 6e 66 6f } //1 /api/keywords-info
		$a_01_4 = {74 65 6c 70 6f 6f } //1 telpoo
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}