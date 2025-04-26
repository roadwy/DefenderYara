
rule Trojan_AndroidOS_Ahmythspy_I{
	meta:
		description = "Trojan:AndroidOS/Ahmythspy.I,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_01_0 = {78 30 30 30 30 6d 63 } //2 x0000mc
		$a_01_1 = {4d 69 63 4d 61 6e 61 67 65 72 } //2 MicManager
		$a_01_2 = {43 61 6d 65 72 61 4d 61 6e 61 67 65 72 24 31 } //2 CameraManager$1
		$a_01_3 = {75 6e 68 69 64 65 5f 70 68 6f 6e 65 5f 6e 75 6d 62 65 72 } //1 unhide_phone_number
		$a_01_4 = {78 30 30 30 30 66 6d } //1 x0000fm
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=7
 
}