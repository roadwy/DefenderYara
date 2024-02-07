
rule TrojanSpy_AndroidOS_Mekir_B_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Mekir.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,09 00 09 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 65 6e 64 54 65 78 74 4d 65 73 73 61 67 65 } //05 00  sendTextMessage
		$a_01_1 = {4c 63 6f 6d 2f 61 6e 64 72 6f 69 64 2f 64 65 76 69 63 65 69 6e 66 6f 2f 6c 69 73 74 65 6e 65 72 } //01 00  Lcom/android/deviceinfo/listener
		$a_01_2 = {72 65 6d 6f 76 65 41 63 74 69 76 65 41 64 6d 69 6e } //01 00  removeActiveAdmin
		$a_01_3 = {6c 6f 63 6b 4e 6f 77 } //01 00  lockNow
		$a_01_4 = {2e 61 70 6b } //00 00  .apk
	condition:
		any of ($a_*)
 
}