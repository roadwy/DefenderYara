
rule Trojan_AndroidOS_Lockscreen_E{
	meta:
		description = "Trojan:AndroidOS/Lockscreen.E,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 71 69 68 6f 6f 2e 6a 69 61 67 75 74 72 61 63 6b 65 72 } //1 com.qihoo.jiagutracker
		$a_01_1 = {64 65 6c 65 74 65 46 69 6c 65 73 53 74 61 72 74 57 69 74 68 47 69 76 65 6e 53 74 72 69 6e 67 } //1 deleteFilesStartWithGivenString
		$a_01_2 = {33 31 66 36 38 65 61 66 33 61 63 31 33 64 37 30 38 36 39 61 37 61 36 37 36 66 31 32 66 38 63 61 61 32 34 33 34 34 33 33 61 66 36 39 65 62 37 65 63 32 66 30 39 32 31 32 39 39 65 38 33 33 37 63 } //1 31f68eaf3ac13d70869a7a676f12f8caa2434433af69eb7ec2f0921299e8337c
		$a_01_3 = {65 6e 64 20 67 65 74 20 70 61 63 6b 61 67 65 4e 61 6d 65 } //1 end get packageName
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}