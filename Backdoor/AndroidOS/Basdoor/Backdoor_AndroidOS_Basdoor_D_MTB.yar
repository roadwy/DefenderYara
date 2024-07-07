
rule Backdoor_AndroidOS_Basdoor_D_MTB{
	meta:
		description = "Backdoor:AndroidOS/Basdoor.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 0a 00 00 "
		
	strings :
		$a_00_0 = {2f 70 61 6e 65 6c 2e 70 68 70 3f 6c 69 6e 6b } //1 /panel.php?link
		$a_00_1 = {61 63 74 69 6f 6e 3d 68 69 64 65 5f 61 6c 6c 26 61 6e 64 72 6f 69 64 5f 69 64 3d } //1 action=hide_all&android_id=
		$a_00_2 = {61 63 74 69 6f 6e 3d 6c 61 73 74 73 6d 73 26 61 6e 64 72 6f 69 64 5f 69 64 3d } //1 action=lastsms&android_id=
		$a_00_3 = {61 63 74 69 6f 6e 3d 69 6e 73 74 61 6c 6c 26 61 6e 64 72 6f 69 64 5f 69 64 3d } //1 action=install&android_id=
		$a_00_4 = {61 63 74 69 6f 6e 3d 75 70 6c 6f 61 64 26 61 6e 64 72 6f 69 64 5f 69 64 3d } //1 action=upload&android_id=
		$a_00_5 = {61 63 74 69 6f 6e 3d 63 6c 69 70 62 6f 61 72 64 26 61 6e 64 72 6f 69 64 5f 69 64 3d } //1 action=clipboard&android_id=
		$a_00_6 = {61 63 74 69 6f 6e 3d 64 65 76 69 63 65 69 6e 66 6f 26 61 6e 64 72 6f 69 64 5f 69 64 3d } //1 action=deviceinfo&android_id=
		$a_00_7 = {68 69 64 65 41 70 70 49 63 6f 6e } //1 hideAppIcon
		$a_00_8 = {61 6c 6c 2d 73 6d 73 2e 74 78 74 } //1 all-sms.txt
		$a_00_9 = {43 61 6c 6c 5f 4c 6f 67 2e 74 78 74 } //1 Call_Log.txt
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1) >=8
 
}