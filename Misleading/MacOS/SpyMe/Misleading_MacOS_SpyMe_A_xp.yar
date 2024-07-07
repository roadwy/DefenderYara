
rule Misleading_MacOS_SpyMe_A_xp{
	meta:
		description = "Misleading:MacOS/SpyMe.A!xp,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2e 72 65 61 64 70 69 78 65 6c 2e 73 70 79 6d 65 2e 64 61 65 6d 6f 6e 2e 69 6e 73 74 61 6c 6c } //1 com.readpixel.spyme.daemon.install
		$a_00_1 = {2f 4c 69 62 72 61 72 79 2f 50 72 65 66 65 72 65 6e 63 65 73 50 61 6e 65 73 2f 53 70 79 4d 65 } //1 /Library/PreferencesPanes/SpyMe
		$a_00_2 = {53 70 79 4d 65 54 6f 6f 6c 53 55 } //2 SpyMeToolSU
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*2) >=3
 
}