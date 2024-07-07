
rule Trojan_iPhoneOS_FlexiSpy_A_MTB{
	meta:
		description = "Trojan:iPhoneOS/FlexiSpy.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {2f 76 61 72 2f 2e 6c 73 61 6c 63 6f 72 65 2f 73 68 61 72 65 73 2f } //2 /var/.lsalcore/shares/
		$a_00_1 = {25 40 2f 65 74 63 2f 46 6f 72 63 65 4f 75 74 2e 70 6c 69 73 74 } //1 %@/etc/ForceOut.plist
		$a_00_2 = {4d 53 46 53 50 55 74 69 6c 73 } //1 MSFSPUtils
		$a_00_3 = {63 61 70 74 75 72 65 53 74 61 72 74 65 64 3a } //1 captureStarted:
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}