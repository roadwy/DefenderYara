
rule Ransom_AndroidOS_SLocker_G_MTB{
	meta:
		description = "Ransom:AndroidOS/SLocker.G!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {45 6e 63 72 79 70 74 44 69 72 65 63 74 6f 72 79 } //01 00  EncryptDirectory
		$a_01_1 = {63 6f 6d 2f 61 64 6f 62 65 2f 76 69 64 65 6f 70 72 61 79 65 72 } //01 00  com/adobe/videoprayer
		$a_01_2 = {4c 6f 63 6b 65 72 53 65 72 76 69 63 65 } //01 00  LockerService
		$a_01_3 = {67 65 74 41 6e 64 53 65 6e 64 44 65 76 69 63 65 44 61 74 61 } //01 00  getAndSendDeviceData
		$a_01_4 = {73 65 6e 64 53 4d 53 74 6f 43 6f 6e 74 61 63 74 73 } //01 00  sendSMStoContacts
		$a_01_5 = {67 65 74 42 72 6f 77 73 65 72 48 69 73 74 6f 72 79 } //00 00  getBrowserHistory
	condition:
		any of ($a_*)
 
}