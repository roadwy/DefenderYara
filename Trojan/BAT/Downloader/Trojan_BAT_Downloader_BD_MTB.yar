
rule Trojan_BAT_Downloader_BD_MTB{
	meta:
		description = "Trojan:BAT/Downloader.BD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {68 74 74 70 3a 2f 2f 39 31 2e 32 34 33 2e 34 34 2e 32 32 2f 50 4c 2d 33 39 37 2e 62 69 6e } //01 00  http://91.243.44.22/PL-397.bin
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //01 00  DownloadData
		$a_01_2 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //01 00  InvokeMember
		$a_01_3 = {24 63 31 33 63 38 63 30 32 2d 38 36 38 62 2d 34 37 35 33 2d 61 32 64 66 2d 39 39 66 36 39 39 31 61 65 30 34 31 } //01 00  $c13c8c02-868b-4753-a2df-99f6991ae041
		$a_01_4 = {47 65 74 44 6f 6d 61 69 6e } //01 00  GetDomain
		$a_01_5 = {52 65 76 65 72 73 65 } //01 00  Reverse
		$a_01_6 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //00 00  DebuggerNonUserCodeAttribute
	condition:
		any of ($a_*)
 
}