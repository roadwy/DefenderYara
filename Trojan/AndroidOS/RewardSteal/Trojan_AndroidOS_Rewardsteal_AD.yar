
rule Trojan_AndroidOS_Rewardsteal_AD{
	meta:
		description = "Trojan:AndroidOS/Rewardsteal.AD,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {6e 61 76 69 67 61 74 65 54 6f 49 6e 66 6f 41 63 74 69 76 69 74 79 49 66 50 65 72 6d 69 73 73 69 6f 6e 73 47 72 61 6e 74 65 64 } //02 00  navigateToInfoActivityIfPermissionsGranted
		$a_01_1 = {70 33 6e 61 70 70 73 32 2f 53 75 63 63 65 73 73 41 63 74 69 76 69 74 79 } //00 00  p3napps2/SuccessActivity
	condition:
		any of ($a_*)
 
}