
rule Trojan_BAT_Fareit_AD_MTB{
	meta:
		description = "Trojan:BAT/Fareit.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 03 00 "
		
	strings :
		$a_00_0 = {2f 00 00 00 e1 00 00 00 1f 01 00 00 13 01 00 00 03 } //03 00 
		$a_80_1 = {43 68 69 6c 64 57 69 6e } //ChildWin  03 00 
		$a_80_2 = {44 6f 63 6b 43 74 72 6c } //DockCtrl  03 00 
		$a_80_3 = {73 65 74 5f 70 61 73 73 77 6f 72 64 50 72 6f 74 65 63 74 65 64 } //set_passwordProtected  03 00 
		$a_80_4 = {70 72 65 5f 54 72 61 63 6b 69 6e 67 5f 4e 75 6d 62 65 72 } //pre_Tracking_Number  03 00 
		$a_80_5 = {49 6e 6a 65 63 74 } //Inject  03 00 
		$a_80_6 = {55 69 2e 54 72 61 63 6b 69 6e 67 52 65 63 6f 72 64 2e 72 65 73 6f 75 72 63 65 73 } //Ui.TrackingRecord.resources  00 00 
	condition:
		any of ($a_*)
 
}