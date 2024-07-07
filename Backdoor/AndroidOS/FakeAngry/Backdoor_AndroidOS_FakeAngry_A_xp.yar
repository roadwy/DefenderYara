
rule Backdoor_AndroidOS_FakeAngry_A_xp{
	meta:
		description = "Backdoor:AndroidOS/FakeAngry.A!xp,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 08 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2e 63 6d 63 63 2e 6d 6f 62 69 6c 65 76 69 64 65 6f } //1 com.cmcc.mobilevideo
		$a_00_1 = {63 6d 63 63 5f 64 79 6e 61 6d 69 63 5f 6c 6f 67 69 6e } //1 cmcc_dynamic_login
		$a_00_2 = {63 6d 63 63 5f 73 74 61 74 69 63 5f 6c 6f 67 69 6e } //1 cmcc_static_login
		$a_00_3 = {2f 6d 6e 74 2f 73 64 63 61 72 64 2d 65 78 74 2f 2e 6d 6f 62 69 6c 65 76 69 64 65 6f 2f 64 6f 77 6e 6c 6f 61 64 2f } //1 /mnt/sdcard-ext/.mobilevideo/download/
		$a_00_4 = {2f 6c 69 62 74 6d 70 63 70 6c 61 79 65 72 2e 73 6f } //1 /libtmpcplayer.so
		$a_00_5 = {6f 70 68 6f 6e 65 56 32 2f 6f 72 64 65 72 4c 69 73 74 2e 6f 70 68 6f 6e 65 } //1 ophoneV2/orderList.ophone
		$a_00_6 = {3a 2f 2f 63 32 2e 63 6d 76 69 64 65 6f 2e 63 6e 2f 75 67 63 61 70 70 2f 75 70 6c 6f 61 64 46 69 6c 65 2f 3d } //1 ://c2.cmvideo.cn/ugcapp/uploadFile/=
		$a_00_7 = {2f 75 67 63 61 70 70 2f 75 70 6c 6f 61 64 46 69 6c 65 2f } //1 /ugcapp/uploadFile/
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=3
 
}