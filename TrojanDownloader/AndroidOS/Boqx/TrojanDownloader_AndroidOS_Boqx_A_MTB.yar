
rule TrojanDownloader_AndroidOS_Boqx_A_MTB{
	meta:
		description = "TrojanDownloader:AndroidOS/Boqx.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {6c 71 73 2f 6a 69 61 6e 6a 69 61 6e 2f 77 61 6c 6c 70 61 70 65 72 2f 71 63 6e 68 } //2 lqs/jianjian/wallpaper/qcnh
		$a_00_1 = {2f 64 6f 77 6e 6c 6f 61 64 2f 2e 75 6d 2f 61 70 6b } //1 /download/.um/apk
		$a_00_2 = {74 61 6c 6b 70 68 6f 6e 65 2e 63 6e 2f 44 6f 77 6e 2f 73 6f 66 74 64 6f 77 6e 6c 6f 61 64 2e 61 73 70 78 } //1 talkphone.cn/Down/softdownload.aspx
		$a_00_3 = {63 6f 6d 2f 61 70 2f 55 74 69 6c 73 } //1 com/ap/Utils
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}