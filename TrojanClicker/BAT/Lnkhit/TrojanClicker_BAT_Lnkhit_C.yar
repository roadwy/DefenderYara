
rule TrojanClicker_BAT_Lnkhit_C{
	meta:
		description = "TrojanClicker:BAT/Lnkhit.C,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 00 73 00 76 00 63 00 75 00 70 00 64 00 61 00 74 00 65 00 2e 00 } //01 00  \svcupdate.
		$a_01_1 = {5c 00 73 00 76 00 63 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 } //01 00  \svchost.exe
		$a_01_2 = {2f 00 69 00 6e 00 2e 00 70 00 68 00 70 00 } //01 00  /in.php
		$a_01_3 = {63 00 6c 00 69 00 63 00 6b 00 73 00 20 00 6c 00 65 00 66 00 74 00 } //00 00  clicks left
	condition:
		any of ($a_*)
 
}