
rule Trojan_MacOS_JaskaGO_A_MTB{
	meta:
		description = "Trojan:MacOS/JaskaGO.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {2a 73 74 65 61 6c 65 72 2e 42 72 6f 77 73 65 72 } //01 00  *stealer.Browser
		$a_01_1 = {42 72 6f 77 73 65 72 45 78 69 73 74 73 } //01 00  BrowserExists
		$a_01_2 = {47 65 74 43 68 72 6f 6d 69 75 6d 50 72 6f 66 69 6c 65 44 61 74 61 } //01 00  GetChromiumProfileData
		$a_01_3 = {2f 67 61 72 79 2d 6d 61 63 6f 73 2d 73 74 65 61 6c 65 72 2d 6d 61 6c 77 61 72 65 2f 61 67 65 6e 74 2f 73 74 65 61 6c 65 72 } //01 00  /gary-macos-stealer-malware/agent/stealer
		$a_01_4 = {67 65 74 57 61 6c 6c 65 74 44 61 74 61 } //00 00  getWalletData
	condition:
		any of ($a_*)
 
}