
rule Trojan_AndroidOS_Rootnik_D_MTB{
	meta:
		description = "Trojan:AndroidOS/Rootnik.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {73 79 73 74 65 6d 2f 61 70 70 2f 75 73 62 75 73 61 67 65 73 65 72 76 69 63 65 69 6e 66 6f 2e 61 70 6b } //1 system/app/usbusageserviceinfo.apk
		$a_00_1 = {26 72 65 62 6f 6f 74 63 6f 75 6e 74 3d } //1 &rebootcount=
		$a_00_2 = {26 6f 73 72 75 6e 74 69 6d 65 3d } //1 &osruntime=
		$a_00_3 = {74 69 63 74 6f 70 2e 70 68 6f 74 6f 74 6f 76 69 64 65 6f 6d 61 6b 65 72 32 } //1 tictop.phototovideomaker2
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}