
rule TrojanSpy_AndroidOS_FakeInst_F_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/FakeInst.F!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 67 6f 6f 67 6c 65 2f 6d 65 64 69 61 2f 73 69 67 6e 65 72 } //1 com/google/media/signer
		$a_01_1 = {70 61 6e 64 6f 72 61 30 30 2e 72 75 } //1 pandora00.ru
		$a_01_2 = {41 45 53 63 72 65 65 6e 4f 66 66 52 65 63 65 69 76 65 72 } //1 AEScreenOffReceiver
		$a_01_3 = {53 65 6e 64 55 73 65 72 44 61 74 61 } //1 SendUserData
		$a_01_4 = {43 6f 6e 74 61 63 74 73 33 39 39 35 } //1 Contacts3995
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}