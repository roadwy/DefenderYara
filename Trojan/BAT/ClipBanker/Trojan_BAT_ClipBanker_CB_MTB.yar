
rule Trojan_BAT_ClipBanker_CB_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.CB!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 00 64 00 6f 00 62 00 65 00 43 00 6f 00 6e 00 66 00 69 00 67 00 2e 00 74 00 78 00 74 00 } //01 00  AdobeConfig.txt
		$a_01_1 = {76 00 61 00 6e 00 69 00 74 00 79 00 41 00 64 00 64 00 72 00 65 00 73 00 73 00 65 00 73 00 } //01 00  vanityAddresses
		$a_01_2 = {41 00 64 00 6f 00 62 00 65 00 55 00 70 00 64 00 61 00 74 00 65 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //01 00  AdobeUpdate.Properties.Resources
		$a_01_3 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //00 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Run
	condition:
		any of ($a_*)
 
}