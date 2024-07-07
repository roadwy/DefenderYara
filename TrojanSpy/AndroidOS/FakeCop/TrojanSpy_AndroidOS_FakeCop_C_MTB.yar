
rule TrojanSpy_AndroidOS_FakeCop_C_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/FakeCop.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {2f 73 79 73 74 65 6d 2f 61 70 70 2f 53 75 70 65 72 75 73 65 72 2e 61 70 6b } //2 /system/app/Superuser.apk
		$a_01_1 = {68 74 74 70 3a 2f 2f 6e 69 6d 61 62 69 37 2e 67 6e 77 61 79 2e 63 63 2f 73 65 6f 75 6c 2f 6b 69 63 73 2f 6c 6f 67 69 6e 2e 68 74 6d 6c } //1 http://nimabi7.gnway.cc/seoul/kics/login.html
		$a_01_2 = {63 6f 6d 2e 63 72 61 7a 79 70 69 67 2e 77 61 77 61 } //1 com.crazypig.wawa
		$a_01_3 = {74 5f 66 6c 69 62 2e 64 62 } //1 t_flib.db
		$a_01_4 = {73 74 61 72 74 64 65 6c 65 74 65 3a 2f 2f } //1 startdelete://
		$a_01_5 = {20 52 6f 6f 74 65 64 } //1  Rooted
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}