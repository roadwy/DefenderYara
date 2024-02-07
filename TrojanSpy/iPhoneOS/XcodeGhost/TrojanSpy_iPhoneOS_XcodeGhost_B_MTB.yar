
rule TrojanSpy_iPhoneOS_XcodeGhost_B_MTB{
	meta:
		description = "TrojanSpy:iPhoneOS/XcodeGhost.B!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_00_0 = {66 5f 74 74 2e 69 70 68 6f 6e 65 73 70 69 72 69 74 2e 63 6f 6d } //01 00  f_tt.iphonespirit.com
		$a_00_1 = {69 70 68 6f 6e 65 74 77 6f 2e 6b 75 61 69 79 6f 6e 67 2e 63 6f 6d 2f 69 2f 69 2e 70 68 70 } //01 00  iphonetwo.kuaiyong.com/i/i.php
		$a_00_2 = {63 6f 6d 2e 74 65 6e 63 65 6e 74 2e 78 69 6e } //01 00  com.tencent.xin
		$a_00_3 = {69 70 68 6f 6e 65 61 70 70 2e 6b 75 61 69 79 6f 6e 67 2e 63 6f 6d } //00 00  iphoneapp.kuaiyong.com
		$a_00_4 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}