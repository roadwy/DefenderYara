
rule Adware_AndroidOS_Feiad_A_MTB{
	meta:
		description = "Adware:AndroidOS/Feiad.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 61 64 66 65 69 77 6f 2f } //1 com/adfeiwo/
		$a_01_1 = {73 68 6f 77 41 64 } //1 showAd
		$a_01_2 = {2f 61 64 66 65 69 77 6f 2f 61 70 70 77 61 6c 6c 2f 61 70 6b } //1 /adfeiwo/appwall/apk
		$a_01_3 = {63 6f 6d 2f 73 65 6c 65 75 63 6f 2f 6d 61 6d 65 34 61 6c 6c } //1 com/seleuco/mame4all
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}