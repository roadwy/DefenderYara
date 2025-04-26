
rule Trojan_BAT_Zusy_CCIB_MTB{
	meta:
		description = "Trojan:BAT/Zusy.CCIB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {4c 6f 67 44 65 63 72 79 70 74 65 64 } //1 LogDecrypted
		$a_01_1 = {4c 6f 67 45 6e 63 72 79 70 74 65 64 } //1 LogEncrypted
		$a_01_2 = {45 6e 63 72 79 70 74 46 69 6c 65 53 79 73 74 65 6d } //1 EncryptFileSystem
		$a_01_3 = {44 65 6c 65 74 65 41 6c 6c 44 72 69 76 65 43 6f 6e 74 65 6e 74 73 } //1 DeleteAllDriveContents
		$a_01_4 = {45 6e 63 72 79 70 74 44 72 69 76 65 43 6f 6e 74 65 6e 74 73 } //1 EncryptDriveContents
		$a_01_5 = {4f 70 65 6e 34 32 30 50 6f 72 74 } //1 Open420Port
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}