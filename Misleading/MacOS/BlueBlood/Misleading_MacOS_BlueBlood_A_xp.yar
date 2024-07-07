
rule Misleading_MacOS_BlueBlood_A_xp{
	meta:
		description = "Misleading:MacOS/BlueBlood.A!xp,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_00_0 = {42 72 6f 77 73 65 72 49 6e 6a 65 63 74 6f 72 45 78 74 2e 62 75 6e 64 6c 65 } //2 BrowserInjectorExt.bundle
		$a_00_1 = {74 6d 70 2f 46 6c 65 78 69 53 50 59 } //1 tmp/FlexiSPY
		$a_00_2 = {6d 61 63 68 5f 69 6e 6a 65 63 74 5f 62 75 6e 64 6c 65 } //1 mach_inject_bundle
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=4
 
}