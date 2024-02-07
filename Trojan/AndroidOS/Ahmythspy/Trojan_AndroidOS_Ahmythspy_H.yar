
rule Trojan_AndroidOS_Ahmythspy_H{
	meta:
		description = "Trojan:AndroidOS/Ahmythspy.H,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_00_0 = {78 30 30 30 30 73 6d } //02 00  x0000sm
		$a_00_1 = {26 64 65 66 61 75 6c 74 5f 64 69 61 6c 65 72 5f 70 61 63 6b 61 67 65 5f 6e 61 6d 65 3d } //01 00  &default_dialer_package_name=
		$a_00_2 = {73 69 6e 67 6c 65 43 6f 6d 6d 61 6e 64 46 65 65 64 42 61 63 6b } //01 00  singleCommandFeedBack
		$a_00_3 = {2f 43 61 6c 6c 4c 69 73 74 65 6e 24 61 } //00 00  /CallListen$a
	condition:
		any of ($a_*)
 
}