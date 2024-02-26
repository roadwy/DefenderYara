
rule Trojan_Win32_ShipUp_GMQ_MTB{
	meta:
		description = "Trojan:Win32/ShipUp.GMQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 0a 00 "
		
	strings :
		$a_03_0 = {08 fa 23 6e e8 2d 90 01 04 93 34 9e c1 66 eb 76 48 90 00 } //01 00 
		$a_01_1 = {40 2e 74 68 65 6d 69 64 61 } //01 00  @.themida
		$a_01_2 = {72 63 73 65 30 75 6e 69 38 } //01 00  rcse0uni8
		$a_01_3 = {49 65 45 53 69 2e 57 69 40 69 } //00 00  IeESi.Wi@i
	condition:
		any of ($a_*)
 
}