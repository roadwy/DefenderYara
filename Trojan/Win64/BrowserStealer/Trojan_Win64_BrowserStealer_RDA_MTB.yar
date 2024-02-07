
rule Trojan_Win64_BrowserStealer_RDA_MTB{
	meta:
		description = "Trojan:Win64/BrowserStealer.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {83 e1 07 0f b6 4c 0d b7 32 0c 02 48 8d 45 d7 49 83 ff 10 49 0f 43 c6 88 0c 02 41 ff c0 48 ff c2 49 63 c8 4c 8b 7d ef 4c 8b 75 d7 48 3b 4b 10 } //01 00 
		$a_01_1 = {5c 4d 6f 7a 69 6c 6c 61 5c 46 69 72 65 66 6f 78 5c 50 72 6f 66 69 6c 65 73 } //00 00  \Mozilla\Firefox\Profiles
	condition:
		any of ($a_*)
 
}