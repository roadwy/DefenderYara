
rule TrojanSpy_AndroidOS_SmsSpy_C{
	meta:
		description = "TrojanSpy:AndroidOS/SmsSpy.C,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {44 69 76 69 63 65 49 6e 66 6f } //1 DiviceInfo
		$a_00_1 = {26 70 6f 72 74 3d 66 75 63 6b 6d 61 72 73 } //1 &port=fuckmars
		$a_00_2 = {2f 72 61 74 2e 70 68 70 } //1 /rat.php
		$a_00_3 = {2f 75 70 6c 6f 61 64 2e 70 68 70 3f } //1 /upload.php?
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}