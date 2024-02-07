
rule Trojan_BAT_NanoBot_ABS_MTB{
	meta:
		description = "Trojan:BAT/NanoBot.ABS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 05 00 "
		
	strings :
		$a_01_0 = {57 1d a2 09 09 0f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 63 00 00 00 15 00 00 00 49 00 00 00 80 00 00 00 5a 00 00 00 d6 00 00 00 } //01 00 
		$a_01_1 = {44 6f 77 64 2e 54 72 65 65 56 69 65 77 2e 72 65 73 6f 75 72 63 65 73 } //01 00  Dowd.TreeView.resources
		$a_01_2 = {47 65 74 4d 65 74 68 6f 64 } //01 00  GetMethod
		$a_01_3 = {49 6e 76 6f 6b 65 } //01 00  Invoke
		$a_01_4 = {47 65 74 4f 62 6a 65 63 74 } //01 00  GetObject
		$a_01_5 = {24 42 31 36 32 34 45 34 33 2d 46 36 41 38 2d 34 36 41 35 2d 39 32 34 38 2d 38 32 31 38 43 43 45 31 43 34 30 33 } //00 00  $B1624E43-F6A8-46A5-9248-8218CCE1C403
	condition:
		any of ($a_*)
 
}