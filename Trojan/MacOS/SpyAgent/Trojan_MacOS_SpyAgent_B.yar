
rule Trojan_MacOS_SpyAgent_B{
	meta:
		description = "Trojan:MacOS/SpyAgent.B,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {41 0f b6 f8 40 30 3c 32 8d 44 07 1f 48 89 c7 49 0f af f9 48 c1 ef 27 69 ff fb 00 00 00 29 f8 48 ff c6 41 89 c0 48 39 f1 75 d6 } //01 00 
		$a_00_1 = {6c 61 75 6e 63 68 63 74 6c 20 73 74 6f 70 20 63 6f 6d 2e 61 70 70 6c 65 2e 74 63 63 64 } //01 00  launchctl stop com.apple.tccd
		$a_00_2 = {63 73 72 75 74 69 6c 20 73 74 61 74 75 73 20 7c 20 67 72 65 70 20 64 69 73 61 62 6c 65 64 } //00 00  csrutil status | grep disabled
	condition:
		any of ($a_*)
 
}