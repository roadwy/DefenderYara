
rule Trojan_AndroidOS_SAgnt_BD_MTB{
	meta:
		description = "Trojan:AndroidOS/SAgnt.BD!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {61 6e 64 72 6f 69 64 2e 70 68 70 3f 64 65 76 69 63 65 5f 62 3d } //1 android.php?device_b=
		$a_01_1 = {6e 75 6d 62 65 72 2e 70 68 70 3f 6e 3d } //1 number.php?n=
		$a_01_2 = {6c 75 6d 65 2f 61 63 74 69 76 69 74 79 2f 61 70 70 } //1 lume/activity/app
		$a_01_3 = {73 6d 73 2e 68 74 6d 6c } //1 sms.html
		$a_01_4 = {67 6f 4d 65 73 73 61 67 65 } //1 goMessage
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}