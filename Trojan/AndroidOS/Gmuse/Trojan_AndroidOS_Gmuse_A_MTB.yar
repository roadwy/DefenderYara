
rule Trojan_AndroidOS_Gmuse_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Gmuse.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 68 65 6e 67 73 68 69 74 69 61 6e 61 69 2e 63 6f 6d 2f 75 70 64 61 74 65 2e 74 78 74 } //1 shengshitianai.com/update.txt
		$a_01_1 = {69 73 75 70 64 61 74 65 } //1 isupdate
		$a_01_2 = {2f 73 64 63 61 72 64 2f 2e 6e 6f 66 69 6c 65 2f 2e 61 6e 64 72 6f 69 64 2f 2e 73 68 6f 77 } //1 /sdcard/.nofile/.android/.show
		$a_01_3 = {73 64 63 61 72 64 2f 6c 69 67 68 74 62 6f 78 2e 61 70 6b } //1 sdcard/lightbox.apk
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}