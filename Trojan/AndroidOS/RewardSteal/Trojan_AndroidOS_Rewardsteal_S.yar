
rule Trojan_AndroidOS_Rewardsteal_S{
	meta:
		description = "Trojan:AndroidOS/Rewardsteal.S,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 53 6d 73 4c 6f 67 20 57 48 45 52 45 20 54 69 6d 65 53 74 61 6d 70 20 3d 20 3f } //2 SELECT * FROM SmsLog WHERE TimeStamp = ?
		$a_01_1 = {43 52 45 41 54 45 20 54 41 42 4c 45 20 53 6d 73 4c 6f 67 20 28 53 6d 73 49 64 20 54 45 58 54 2c 20 53 6d 73 41 64 64 72 65 73 73 20 54 45 58 54 2c 53 6d 73 42 6f 64 79 20 54 45 58 54 2c 53 6d 73 44 61 74 65 54 69 6d 65 20 54 45 58 54 2c 54 69 6d 65 53 74 61 6d 70 20 54 45 58 54 29 } //2 CREATE TABLE SmsLog (SmsId TEXT, SmsAddress TEXT,SmsBody TEXT,SmsDateTime TEXT,TimeStamp TEXT)
		$a_01_2 = {72 65 77 61 72 64 32 2f 72 65 77 61 72 64 73 63 72 65 65 6e } //2 reward2/rewardscreen
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=4
 
}