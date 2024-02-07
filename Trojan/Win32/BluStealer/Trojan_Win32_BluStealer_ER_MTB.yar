
rule Trojan_Win32_BluStealer_ER_MTB{
	meta:
		description = "Trojan:Win32/BluStealer.ER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 00 72 00 79 00 70 00 74 00 6f 00 57 00 61 00 6c 00 6c 00 65 00 74 00 73 00 2e 00 7a 00 69 00 70 00 } //01 00  CryptoWallets.zip
		$a_01_1 = {61 00 70 00 69 00 2e 00 74 00 65 00 6c 00 65 00 67 00 72 00 61 00 6d 00 2e 00 6f 00 72 00 67 00 2f 00 62 00 6f 00 74 00 } //01 00  api.telegram.org/bot
		$a_01_2 = {46 00 69 00 6c 00 65 00 73 00 47 00 72 00 61 00 62 00 62 00 65 00 72 00 } //01 00  FilesGrabber
		$a_01_3 = {74 72 20 65 20 6e 75 20 6e 69 53 4f 44 6f 6d 20 2e 65 64 } //01 00  tr e nu niSODom .ed
		$a_01_4 = {43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 4f 00 6e 00 63 00 65 00 5c 00 2a 00 52 00 44 00 5f 00 } //01 00  CurrentVersion\RunOnce\*RD_
		$a_01_5 = {54 00 65 00 6d 00 70 00 6c 00 61 00 74 00 65 00 73 00 5c 00 53 00 74 00 75 00 62 00 5c 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 31 00 2e 00 76 00 62 00 70 00 } //00 00  Templates\Stub\Project1.vbp
	condition:
		any of ($a_*)
 
}