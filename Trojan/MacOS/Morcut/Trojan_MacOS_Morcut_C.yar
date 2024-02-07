
rule Trojan_MacOS_Morcut_C{
	meta:
		description = "Trojan:MacOS/Morcut.C,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2e 61 70 70 6c 65 2e 6d 64 77 6f 72 6b 65 72 2e 70 6c 69 73 74 } //01 00  com.apple.mdworker.plist
		$a_00_1 = {6d 64 77 6f 72 6b 65 72 2e 66 6c 67 } //01 00  mdworker.flg
		$a_00_2 = {25 40 3a 73 74 61 66 66 } //01 00  %@:staff
		$a_00_3 = {5f 65 78 65 63 75 74 65 54 61 73 6b } //00 00  _executeTask
		$a_00_4 = {5d 04 00 } //00 b2 
	condition:
		any of ($a_*)
 
}