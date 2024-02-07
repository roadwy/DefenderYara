
rule Ransom_AndroidOS_SimpLock_A{
	meta:
		description = "Ransom:AndroidOS/SimpLock.A,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 73 69 6d 70 6c 65 6c 6f 63 6b 65 72 2f 44 65 63 72 79 70 74 53 65 72 76 69 63 65 } //01 00  /simplelocker/DecryptService
		$a_01_1 = {6a 6e 64 6c 61 73 66 30 37 34 68 72 } //01 00  jndlasf074hr
		$a_01_2 = {44 49 53 41 42 4c 45 5f 4c 4f 43 4b 45 52 } //01 00  DISABLE_LOCKER
		$a_01_3 = {46 49 4c 45 53 5f 57 41 53 5f 45 4e 43 52 59 50 54 45 44 } //01 00  FILES_WAS_ENCRYPTED
		$a_01_4 = {41 45 53 2f 43 42 43 2f 50 4b 43 53 37 50 61 64 64 69 6e 67 } //01 00  AES/CBC/PKCS7Padding
		$a_01_5 = {6c 6f 63 6b 65 72 20 63 68 65 63 6b } //01 00  locker check
		$a_01_6 = {57 61 6b 65 4c 6f 63 6b } //00 00  WakeLock
	condition:
		any of ($a_*)
 
}