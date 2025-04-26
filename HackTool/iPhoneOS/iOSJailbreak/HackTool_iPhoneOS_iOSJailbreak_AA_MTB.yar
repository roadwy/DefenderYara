
rule HackTool_iPhoneOS_iOSJailbreak_AA_MTB{
	meta:
		description = "HackTool:iPhoneOS/iOSJailbreak.AA!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_00_0 = {75 70 64 61 74 65 2e 39 33 2e 70 61 6e 67 75 2e 69 6f 2f 6a 62 } //1 update.93.pangu.io/jb
		$a_00_1 = {2f 74 6d 70 2f 2e 70 61 6e 67 75 39 33 6c 6f 61 64 65 64 } //1 /tmp/.pangu93loaded
		$a_00_2 = {69 6f 2e 70 61 6e 67 75 39 33 2e 6c 6f 61 64 65 72 2e 70 6c 69 73 74 } //1 io.pangu93.loader.plist
		$a_00_3 = {63 79 64 69 61 3a 2f 2f } //1 cydia://
		$a_00_4 = {63 6f 6d 2e 73 61 75 72 69 6b 2e 63 79 64 69 61 } //1 com.saurik.cydia
		$a_00_5 = {69 6f 2e 70 61 6e 67 75 2e 6e 76 77 61 73 74 6f 6e 65 } //1 io.pangu.nvwastone
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=4
 
}