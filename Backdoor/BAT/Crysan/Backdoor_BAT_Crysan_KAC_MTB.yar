
rule Backdoor_BAT_Crysan_KAC_MTB{
	meta:
		description = "Backdoor:BAT/Crysan.KAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {06 07 02 07 91 03 07 03 8e 69 5d 91 61 d2 9c 07 17 58 0b 07 02 8e 69 32 e7 } //05 00 
		$a_01_1 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 66 00 73 00 2d 00 69 00 6d 00 2d 00 6b 00 65 00 66 00 75 00 2e 00 37 00 6d 00 6f 00 6f 00 72 00 2d 00 66 00 73 00 31 00 2e 00 63 00 6f 00 6d 00 } //00 00  https://fs-im-kefu.7moor-fs1.com
	condition:
		any of ($a_*)
 
}