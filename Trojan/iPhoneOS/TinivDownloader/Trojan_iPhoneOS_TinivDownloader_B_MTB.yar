
rule Trojan_iPhoneOS_TinivDownloader_B_MTB{
	meta:
		description = "Trojan:iPhoneOS/TinivDownloader.B!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {2f 41 70 70 6c 69 63 61 74 69 6f 6e 73 2f 50 50 48 65 6c 70 65 72 4e 53 2e 61 70 70 2f 50 50 48 65 6c 70 65 72 4e 53 } //2 /Applications/PPHelperNS.app/PPHelperNS
		$a_00_1 = {2f 74 6d 70 2f 2e 6e 65 65 64 75 69 63 61 63 68 65 } //1 /tmp/.needuicache
		$a_00_2 = {2f 74 6d 70 2f 2e 70 61 6e 67 75 39 33 6c 6f 61 64 65 64 } //1 /tmp/.pangu93loaded
		$a_00_3 = {3a 2f 2f 69 6d 61 67 65 2e 75 63 2e 63 6e 2f 73 2f 75 61 65 2f 67 2f 32 36 2f 69 6f 73 5f 79 75 65 79 75 74 6f 6f 6c 2f 66 61 71 2e 68 74 6d 6c } //1 ://image.uc.cn/s/uae/g/26/ios_yueyutool/faq.html
		$a_00_4 = {63 79 64 69 61 3a 2f 2f 75 72 6c 2f 66 69 6c 65 3a 2f 2f 25 40 } //1 cydia://url/file://%@
		$a_00_5 = {2f 41 70 70 6c 69 63 61 74 69 6f 6e 73 2f 43 79 64 69 61 2e 61 70 70 } //1 /Applications/Cydia.app
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}