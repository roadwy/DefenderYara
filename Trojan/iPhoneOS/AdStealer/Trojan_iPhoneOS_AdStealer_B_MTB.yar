
rule Trojan_iPhoneOS_AdStealer_B_MTB{
	meta:
		description = "Trojan:iPhoneOS/AdStealer.B!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {6e 61 6d 65 67 65 6e 65 72 61 74 6f 72 2e 70 6c 69 73 74 } //1 namegenerator.plist
		$a_00_1 = {6d 6f 62 69 6c 65 2f 52 52 53 6f 75 74 2f 44 41 54 41 33 66 6f 6c 64 65 72 } //1 mobile/RRSout/DATA3folder
		$a_00_2 = {63 6f 6d 2e 6d 65 6f 79 65 75 2e 66 64 2e 70 6c 69 73 74 } //1 com.meoyeu.fd.plist
		$a_00_3 = {63 79 64 69 61 3a 2f 2f 70 61 63 6b 61 67 65 2f 73 75 64 6f } //1 cydia://package/sudo
		$a_00_4 = {41 6c 6c 20 62 61 63 6b 75 70 20 66 69 6c 65 73 20 77 65 72 65 20 64 65 6c 65 74 65 64 } //1 All backup files were deleted
		$a_00_5 = {6b 69 6c 6c 61 6c 6c 20 2d 39 20 70 72 6f 66 69 6c 65 64 } //1 killall -9 profiled
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=5
 
}