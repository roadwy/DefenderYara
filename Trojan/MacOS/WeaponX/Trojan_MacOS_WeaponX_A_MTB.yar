
rule Trojan_MacOS_WeaponX_A_MTB{
	meta:
		description = "Trojan:MacOS/WeaponX.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2e 6e 65 6d 6f 2e 6b 65 78 74 2e 57 65 61 70 6f 6e 58 } //01 00  com.nemo.kext.WeaponX
		$a_00_1 = {2f 55 73 65 72 73 2f 6e 65 6d 6f 2f 43 6f 64 69 6e 67 2f 57 65 61 70 6f 6e 58 2f } //01 00  /Users/nemo/Coding/WeaponX/
		$a_00_2 = {5f 57 65 61 70 6f 6e 58 5f 73 74 61 72 74 } //01 00  _WeaponX_start
		$a_00_3 = {5f 68 6f 6f 6b 65 64 5f 67 65 74 64 69 72 65 6e 74 72 69 65 73 } //00 00  _hooked_getdirentries
		$a_00_4 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}