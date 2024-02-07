
rule Trojan_MacOS_Morcut_A_MTB{
	meta:
		description = "Trojan:MacOS/Morcut.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {4f 76 7a 44 37 78 46 72 2e 61 70 70 } //01 00  OvzD7xFr.app
		$a_00_1 = {43 3a 5c 52 43 53 44 42 5c 74 6d 70 5c 62 75 69 37 41 31 4f 76 7a 44 37 78 46 72 2e 61 70 70 } //01 00  C:\RCSDB\tmp\bui7A1OvzD7xFr.app
		$a_00_2 = {38 6f 54 48 59 4d 43 6a 2e 58 49 6c } //01 00  8oTHYMCj.XIl
		$a_00_3 = {5f 5f 4d 50 52 45 53 53 5f 5f 76 2e 32 2e 31 32 } //00 00  __MPRESS__v.2.12
		$a_00_4 = {5d 04 00 } //00 e3 
	condition:
		any of ($a_*)
 
}