
rule Trojan_iPhoneOS_KeyRaider_A_xp{
	meta:
		description = "Trojan:iPhoneOS/KeyRaider.A!xp,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {6d 69 73 63 68 61 30 37 } //01 00  mischa07
		$a_00_1 = {77 77 77 2e 77 75 73 68 69 64 6f 75 2e 63 6e } //01 00  www.wushidou.cn
		$a_00_2 = {2f 4c 69 62 72 61 72 79 2f 4d 6f 62 69 6c 65 53 75 62 73 74 72 61 74 65 2f 44 79 6e 61 6d 69 63 4c 69 62 72 61 72 69 65 73 2f 69 77 65 78 69 6e 2e 64 79 6c 69 62 } //01 00  /Library/MobileSubstrate/DynamicLibraries/iwexin.dylib
		$a_00_3 = {2f 75 73 72 2f 6c 69 62 2f 6c 69 62 4d 6f 62 69 6c 65 47 65 73 74 61 6c 74 2e 64 79 6c 69 62 } //01 00  /usr/lib/libMobileGestalt.dylib
		$a_00_4 = {50 4f 53 54 20 2f 57 65 62 4f 62 6a 65 63 74 73 2f 4d 5a 46 69 6e 61 6e 63 65 2e 77 6f 61 2f 77 61 } //01 00  POST /WebObjects/MZFinance.woa/wa
		$a_00_5 = {68 6f 6f 6b 61 69 64 } //01 00  hookaid
		$a_00_6 = {69 61 70 70 73 74 6f 72 65 } //00 00  iappstore
		$a_00_7 = {5d 04 00 00 } //f4 c7 
	condition:
		any of ($a_*)
 
}