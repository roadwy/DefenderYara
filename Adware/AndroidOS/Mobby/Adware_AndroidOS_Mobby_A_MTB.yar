
rule Adware_AndroidOS_Mobby_A_MTB{
	meta:
		description = "Adware:AndroidOS/Mobby.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {69 6f 2f 6d 6f 62 62 79 2f 6c 6f 61 64 65 72 2f 61 70 } //02 00  io/mobby/loader/ap
		$a_01_1 = {43 72 79 6f 6c 6f 61 64 65 72 } //01 00  Cryoloader
		$a_01_2 = {67 65 74 53 65 72 76 65 72 } //02 00  getServer
		$a_01_3 = {72 65 76 6f 6c 75 6d 62 75 73 2e 73 70 61 63 65 } //01 00  revolumbus.space
		$a_01_4 = {73 74 61 72 74 53 65 72 76 69 63 65 } //00 00  startService
	condition:
		any of ($a_*)
 
}