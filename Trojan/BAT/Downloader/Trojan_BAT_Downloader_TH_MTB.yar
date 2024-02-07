
rule Trojan_BAT_Downloader_TH_MTB{
	meta:
		description = "Trojan:BAT/Downloader.TH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_81_0 = {68 74 74 70 73 3a 2f 2f 63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 74 74 61 63 68 6d 65 6e 74 73 } //01 00  https://cdn.discordapp.com/attachments
		$a_81_1 = {44 6f 77 6e 6c 6f 5b 5d 61 64 53 74 72 69 6e 67 } //01 00  Downlo[]adString
		$a_81_2 = {41 70 70 65 6e 5b 5d 64 } //01 00  Appen[]d
		$a_01_3 = {55 6e 73 61 66 65 4e 61 74 69 76 65 4d 65 74 68 6f 64 73 } //01 00  UnsafeNativeMethods
		$a_01_4 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //01 00  DebuggingModes
		$a_01_5 = {52 65 70 6c 61 63 65 } //01 00  Replace
		$a_01_6 = {49 6e 76 6f 6b 65 } //01 00  Invoke
		$a_01_7 = {24 65 38 62 35 35 66 39 31 2d 63 33 32 66 2d 34 38 30 65 2d 39 32 33 33 2d 38 65 61 66 34 34 35 35 34 39 61 63 } //00 00  $e8b55f91-c32f-480e-9233-8eaf445549ac
	condition:
		any of ($a_*)
 
}