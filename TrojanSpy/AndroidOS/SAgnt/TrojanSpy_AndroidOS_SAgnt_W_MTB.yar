
rule TrojanSpy_AndroidOS_SAgnt_W_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SAgnt.W!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 6d 79 31 31 34 2f } //1 com/my114/
		$a_01_1 = {70 68 70 2e 31 31 34 6d 79 2e 63 6f 6d 2e 63 6e 2f 69 6e 64 65 78 2e 70 68 70 3f } //1 php.114my.com.cn/index.php?
		$a_01_2 = {6d 2e 6b 61 6e 67 62 6f 6d 65 63 68 2e 63 6f 6d 3f 74 69 6d 65 73 74 61 6d 70 3d } //1 m.kangbomech.com?timestamp=
		$a_01_3 = {53 75 70 65 72 50 68 6f 6e 65 41 63 74 69 76 69 74 79 } //1 SuperPhoneActivity
		$a_01_4 = {6d 3d 48 6f 6d 65 26 63 3d 45 6d 70 6c 6f 79 65 65 26 61 3d 73 65 74 5f 6c 6f 63 61 74 69 6f 6e } //1 m=Home&c=Employee&a=set_location
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}