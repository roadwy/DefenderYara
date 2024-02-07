
rule TrojanSpy_AndroidOS_BanBra_B_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/BanBra.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {44 65 66 65 6e 73 6f 72 20 49 44 2d 30 31 } //02 00  Defensor ID-01
		$a_00_1 = {3a 2f 2f 65 6d 70 72 65 73 61 73 65 6e 65 67 6f 63 69 6f 73 2e 6f 6e 6c 69 6e 65 2f 72 65 6d 6f 74 65 43 6f 6e 74 72 6f 6c 2f } //01 00  ://empresasenegocios.online/remoteControl/
		$a_00_2 = {44 61 74 61 53 6e 61 70 73 68 6f 74 } //01 00  DataSnapshot
		$a_00_3 = {66 69 72 65 62 61 73 65 43 6d 64 } //01 00  firebaseCmd
		$a_00_4 = {66 69 72 65 62 61 73 65 2f 64 61 74 61 62 61 73 65 2f 63 6f 6e 6e 65 63 74 69 6f 6e 2f 69 64 6c 2f 49 50 65 72 73 69 73 74 65 6e 74 43 6f 6e 6e 65 63 74 69 6f 6e 49 6d 70 6c 24 31 } //00 00  firebase/database/connection/idl/IPersistentConnectionImpl$1
	condition:
		any of ($a_*)
 
}