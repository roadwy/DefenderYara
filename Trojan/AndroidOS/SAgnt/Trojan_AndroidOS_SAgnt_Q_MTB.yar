
rule Trojan_AndroidOS_SAgnt_Q_MTB{
	meta:
		description = "Trojan:AndroidOS/SAgnt.Q!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {62 72 6f 77 73 65 72 75 72 6c 63 6f 6c 6c 65 63 74 6f 72 } //01 00  browserurlcollector
		$a_01_1 = {63 6f 6d 2e 67 65 6d 69 75 73 2e 6e 65 74 70 61 6e 65 6c } //01 00  com.gemius.netpanel
		$a_01_2 = {48 69 74 44 65 74 65 63 74 6f 72 52 65 63 65 69 76 65 72 } //01 00  HitDetectorReceiver
		$a_01_3 = {6d 6f 62 69 6c 65 6d 65 74 65 72 2f 75 69 2f 73 63 72 65 65 6e 2f 4d 61 69 6e 41 63 74 69 76 69 74 79 } //01 00  mobilemeter/ui/screen/MainActivity
		$a_01_4 = {4f 53 43 6f 6c 6c 65 63 74 6f 72 54 61 73 6b } //00 00  OSCollectorTask
	condition:
		any of ($a_*)
 
}