
rule Trojan_AndroidOS_GGTracker_A{
	meta:
		description = "Trojan:AndroidOS/GGTracker.A,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {67 67 74 72 61 63 6b 2e 6f 72 67 2f 53 4d 31 90 01 01 3f 64 65 76 69 63 65 5f 69 64 3d 90 00 } //1
		$a_01_1 = {61 6d 61 7a 30 6e 2d 63 6c 6f 75 64 2e 63 6f 6d 2f 64 72 6f 69 64 2f 64 72 6f 69 64 2e 70 68 70 } //1 amaz0n-cloud.com/droid/droid.php
		$a_01_2 = {74 72 61 63 6b 49 6e 73 74 61 6c 6c } //1 trackInstall
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}