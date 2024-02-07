
rule Trojan_BAT_Heracles_BAA_MTB{
	meta:
		description = "Trojan:BAT/Heracles.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {72 c1 00 00 70 28 90 01 01 00 00 0a 72 ed 00 00 70 28 90 01 01 00 00 0a 26 20 f4 01 00 00 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 2a 90 00 } //02 00 
		$a_01_1 = {76 00 62 00 70 00 61 00 6e 00 65 00 6c 00 2e 00 63 00 6f 00 6d 00 2f 00 70 00 61 00 6e 00 65 00 6c 00 2f 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 2f 00 56 00 65 00 72 00 74 00 69 00 67 00 6f 00 42 00 6f 00 6f 00 73 00 74 00 50 00 61 00 6e 00 65 00 6c 00 2e 00 7a 00 69 00 70 00 } //01 00  vbpanel.com/panel/download/VertigoBoostPanel.zip
		$a_01_2 = {56 00 65 00 72 00 74 00 69 00 67 00 6f 00 42 00 6f 00 6f 00 73 00 74 00 50 00 61 00 6e 00 65 00 6c 00 2e 00 65 00 78 00 65 00 2e 00 63 00 6f 00 6e 00 66 00 69 00 67 00 } //00 00  VertigoBoostPanel.exe.config
	condition:
		any of ($a_*)
 
}