
rule TrojanSpy_AndroidOS_RewardSteal_B_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/RewardSteal.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 6d 79 6b 79 63 61 6e 64 72 6f 69 64 2e } //5 com.mykycandroid.
		$a_01_1 = {63 6f 6d 2f 68 64 72 65 77 61 72 64 2f 70 6f 69 6e 74 73 2f 4d 61 69 6e 41 63 74 69 76 69 74 79 } //5 com/hdreward/points/MainActivity
		$a_01_2 = {26 66 72 6f 6d 3d 61 70 70 } //1 &from=app
		$a_01_3 = {73 65 6e 64 44 61 74 61 } //1 sendData
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=7
 
}