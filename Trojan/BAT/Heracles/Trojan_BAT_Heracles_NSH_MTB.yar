
rule Trojan_BAT_Heracles_NSH_MTB{
	meta:
		description = "Trojan:BAT/Heracles.NSH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {08 07 6f 1b 00 00 0a 07 6f 90 01 01 00 00 0a 28 90 01 01 00 00 2b 28 90 01 01 00 00 2b 0d de 1e 90 00 } //01 00 
		$a_01_1 = {4c 6b 61 6d 70 61 72 71 63 } //01 00  Lkamparqc
		$a_01_2 = {57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 31 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //00 00  WindowsFormsApp1.Properties.Resources
	condition:
		any of ($a_*)
 
}