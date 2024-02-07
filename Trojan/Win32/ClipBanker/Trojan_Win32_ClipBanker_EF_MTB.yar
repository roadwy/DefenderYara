
rule Trojan_Win32_ClipBanker_EF_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.EF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 08 00 00 03 00 "
		
	strings :
		$a_81_0 = {53 74 61 72 74 47 72 61 62 62 69 6e 67 } //03 00  StartGrabbing
		$a_81_1 = {5e 28 62 63 31 7c 5b 31 33 5d 29 5b 61 2d 7a 41 2d 48 4a 2d 4e 50 2d 5a 30 2d 39 5d 7b 32 35 2c 33 39 7d 24 } //03 00  ^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$
		$a_81_2 = {5e 30 78 5b 61 2d 66 41 2d 46 30 2d 39 5d 7b 34 30 7d 24 } //03 00  ^0x[a-fA-F0-9]{40}$
		$a_81_3 = {72 65 74 72 69 65 76 65 5f 49 6e 66 6f } //03 00  retrieve_Info
		$a_81_4 = {69 6e 73 74 61 6c 6c 65 64 20 74 68 65 20 63 6c 69 70 70 65 72 } //03 00  installed the clipper
		$a_81_5 = {79 6f 75 72 42 43 48 41 64 64 72 65 73 73 } //03 00  yourBCHAddress
		$a_81_6 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //03 00  DownloadString
		$a_81_7 = {73 65 6e 64 54 6f 48 6f 6f 6b } //00 00  sendToHook
	condition:
		any of ($a_*)
 
}