
rule Ransom_AndroidOS_SLocker_F_MTB{
	meta:
		description = "Ransom:AndroidOS/SLocker.F!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {74 78 2f 71 71 38 39 38 35 30 37 33 33 39 2f 62 7a 79 39 } //01 00  tx/qq898507339/bzy9
		$a_00_1 = {67 65 74 43 75 73 74 6f 6d 43 6c 61 73 73 4c 6f 61 64 65 72 } //01 00  getCustomClassLoader
		$a_00_2 = {67 65 74 41 43 61 6c 6c } //01 00  getACall
		$a_00_3 = {2f 53 6d 73 52 65 63 65 69 76 65 72 } //00 00  /SmsReceiver
	condition:
		any of ($a_*)
 
}