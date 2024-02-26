
rule Trojan_Win64_BrookStealer_DA_MTB{
	meta:
		description = "Trojan:Win64/BrookStealer.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {42 72 6f 6f 6b 53 74 65 61 6c 65 72 } //01 00  BrookStealer
		$a_01_1 = {47 72 61 62 42 72 6f 77 73 65 72 50 61 73 73 77 6f 72 64 73 } //01 00  GrabBrowserPasswords
		$a_01_2 = {62 72 6f 77 73 65 72 2e 43 72 65 64 65 6e 74 69 61 6c } //01 00  browser.Credential
		$a_01_3 = {46 69 72 65 66 6f 78 43 72 61 63 6b 4c 6f 67 69 6e 44 61 74 61 } //00 00  FirefoxCrackLoginData
	condition:
		any of ($a_*)
 
}