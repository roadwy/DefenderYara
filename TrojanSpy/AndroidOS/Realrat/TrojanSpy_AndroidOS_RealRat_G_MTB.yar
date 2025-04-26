
rule TrojanSpy_AndroidOS_RealRat_G_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/RealRat.G!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,09 00 09 00 06 00 00 "
		
	strings :
		$a_00_0 = {6f 6e 53 74 61 72 74 43 6f 6d 6d 61 6e 64 } //2 onStartCommand
		$a_00_1 = {5f 73 65 72 76 69 63 65 5f 73 74 61 72 74 } //2 _service_start
		$a_00_2 = {2f 72 65 63 65 69 76 65 2e 70 68 70 } //2 /receive.php
		$a_00_3 = {67 65 74 48 69 6e 74 48 69 64 65 49 63 6f 6e } //2 getHintHideIcon
		$a_00_4 = {6b 61 72 64 61 72 6d 61 6e 7a 65 6c 2e 67 71 } //1 kardarmanzel.gq
		$a_00_5 = {6c 6f 72 64 72 65 6d 6f 74 65 2e 78 79 7a } //1 lordremote.xyz
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=9
 
}