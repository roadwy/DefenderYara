
rule Trojan_BAT_FileCoder_MD_MTB{
	meta:
		description = "Trojan:BAT/FileCoder.MD!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 69 73 61 62 6c 65 52 65 63 6f 76 65 72 79 4d 6f 64 65 } //01 00  disableRecoveryMode
		$a_01_1 = {63 68 65 63 6b 41 64 6d 69 6e 50 72 69 76 69 6c 61 67 65 } //01 00  checkAdminPrivilage
		$a_01_2 = {64 65 6c 65 74 65 53 68 61 64 6f 77 43 6f 70 69 65 73 } //01 00  deleteShadowCopies
		$a_01_3 = {65 6e 63 72 79 70 74 65 64 46 69 6c 65 45 78 74 65 6e 73 69 6f 6e } //00 00  encryptedFileExtension
	condition:
		any of ($a_*)
 
}