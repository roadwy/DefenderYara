
rule TrojanDropper_AndroidOS_Rootnik_B_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/Rootnik.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {64 65 76 5f 72 6f 6f 74 32 } //1 dev_root2
		$a_00_1 = {72 6f 6f 74 69 6e 67 20 75 73 69 6e 67 20 70 61 63 6b 61 67 65 } //1 rooting using package
		$a_00_2 = {69 73 20 72 6f 6f 74 65 64 } //1 is rooted
		$a_00_3 = {70 6d 20 69 6e 73 74 61 6c 6c 20 2d 72 } //1 pm install -r
		$a_00_4 = {75 70 64 61 74 65 20 72 6f 6f 74 20 64 62 } //1 update root db
		$a_00_5 = {70 75 73 68 2e 61 70 6b } //1 push.apk
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}