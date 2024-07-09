
rule TrojanSpy_AndroidOS_Fakecalls_B_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Fakecalls.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_03_0 = {63 68 61 6f 77 65 6e 30 [0-02] 2e 63 6f 6d } //5
		$a_03_1 = {77 65 6e 64 69 6e 67 30 [0-02] 2e 63 6f 6d } //5
		$a_03_2 = {50 68 6f 6e 65 43 61 6c 6c [0-08] 53 65 72 76 69 63 65 } //1
		$a_03_3 = {63 6f 6d 2f [0-08] 2f 72 74 6d 70 5f 63 6c 69 65 6e 74 } //1
		$a_01_4 = {2f 64 65 76 69 63 65 2f 67 65 74 74 72 61 6e 73 66 65 72 3f 6e 75 6d 62 65 72 3d } //1 /device/gettransfer?number=
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1) >=7
 
}