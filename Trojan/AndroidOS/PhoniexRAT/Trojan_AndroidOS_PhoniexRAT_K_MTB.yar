
rule Trojan_AndroidOS_PhoniexRAT_K_MTB{
	meta:
		description = "Trojan:AndroidOS/PhoniexRAT.K!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 0a 00 00 02 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2f 73 65 72 76 69 63 65 2f 61 70 70 2f 49 6e 64 65 78 41 43 54 } //01 00  com/service/app/IndexACT
		$a_00_1 = {75 72 6c 41 64 6d 69 6e 50 61 6e 65 6c } //01 00  urlAdminPanel
		$a_00_2 = {73 77 61 70 73 6d 73 6d 65 6e 61 67 65 72 } //01 00  swapsmsmenager
		$a_00_3 = {77 68 69 6c 65 53 74 61 72 74 55 70 64 61 74 65 49 6e 65 63 74 69 6f 6e } //01 00  whileStartUpdateInection
		$a_00_4 = {73 74 61 72 74 4b 69 6e 67 53 65 72 76 69 63 65 } //01 00  startKingService
		$a_00_5 = {63 68 65 63 6b 75 70 64 61 74 65 49 6e 6a 65 63 74 69 6f 6e } //01 00  checkupdateInjection
		$a_00_6 = {53 63 72 65 65 6e 53 74 61 74 75 73 } //01 00  ScreenStatus
		$a_00_7 = {67 6f 4f 66 66 50 72 6f 74 65 63 74 } //01 00  goOffProtect
		$a_00_8 = {75 70 64 61 74 65 69 6e 6a 65 63 74 61 6e 64 6c 69 73 74 61 70 70 73 } //01 00  updateinjectandlistapps
		$a_00_9 = {75 70 64 61 74 65 42 6f 74 50 61 72 61 6d 73 } //00 00  updateBotParams
	condition:
		any of ($a_*)
 
}