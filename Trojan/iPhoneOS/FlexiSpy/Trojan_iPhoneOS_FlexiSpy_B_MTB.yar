
rule Trojan_iPhoneOS_FlexiSpy_B_MTB{
	meta:
		description = "Trojan:iPhoneOS/FlexiSpy.B!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {6b 69 6c 6c 61 6c 6c 20 4d 6f 62 69 6c 65 4d 61 69 6c } //01 00  killall MobileMail
		$a_00_1 = {25 40 2f 65 74 63 2f 46 6f 72 63 65 4f 75 74 2e 70 6c 69 73 74 } //01 00  %@/etc/ForceOut.plist
		$a_00_2 = {64 65 76 69 70 68 6f 6e 65 76 32 74 40 67 6d 61 69 6c 2e 63 6f 6d } //01 00  deviphonev2t@gmail.com
		$a_00_3 = {73 65 74 4d 43 61 6d 65 72 61 53 74 61 72 74 43 61 70 74 75 72 65 } //00 00  setMCameraStartCapture
		$a_00_4 = {5d 04 00 } //00 76 
	condition:
		any of ($a_*)
 
}