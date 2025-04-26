
rule Trojan_AndroidOS_SmsThief_IY{
	meta:
		description = "Trojan:AndroidOS/SmsThief.IY,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 74 6f 72 65 53 6d 73 49 6e 46 69 72 65 62 61 73 65 } //2 storeSmsInFirebase
		$a_01_1 = {43 52 45 41 54 45 20 54 41 42 4c 45 20 49 46 20 4e 4f 54 20 45 58 49 53 54 53 20 70 68 6f 6e 65 20 28 70 68 6f 6e 65 20 54 45 58 54 29 } //2 CREATE TABLE IF NOT EXISTS phone (phone TEXT)
		$a_01_2 = {69 63 69 63 69 2f 44 42 48 61 6e 64 6c 65 72 } //2 icici/DBHandler
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=4
 
}