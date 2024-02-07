
rule Adware_MacOS_MacSearch_A_MTB{
	meta:
		description = "Adware:MacOS/MacSearch.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {a3 8b ff 66 ab 4c fe 1d 74 5f f5 62 42 f2 59 ed 0b 2c 34 e0 53 45 38 00 cc 8e f2 5a 58 a0 77 22 b2 a2 e2 81 58 fb 48 ba f5 f5 63 bc 14 6d 26 1f 73 42 25 37 e0 90 28 f3 ea e1 d4 76 cc db 16 de 5c 3d ba e4 c9 5c 92 18 96 c6 1b 57 73 79 d8 d3 c7 61 0f fb 46 c5 df 7a 0a d6 9c 3a ec 8a 85 ec } //01 00 
		$a_00_1 = {53 61 66 61 72 69 53 65 61 72 63 68 41 70 70 45 78 74 65 6e 73 69 6f 6e } //00 00  SafariSearchAppExtension
	condition:
		any of ($a_*)
 
}