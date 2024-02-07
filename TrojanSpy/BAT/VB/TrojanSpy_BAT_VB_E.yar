
rule TrojanSpy_BAT_VB_E{
	meta:
		description = "TrojanSpy:BAT/VB.E,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {46 00 54 00 50 00 20 00 4e 00 61 00 6d 00 65 00 3a 00 } //02 00  FTP Name:
		$a_01_1 = {53 63 72 65 65 6e 5f 53 74 65 61 6c 65 72 2e 52 65 73 6f 75 72 63 65 73 } //01 00  Screen_Stealer.Resources
		$a_00_2 = {5c 00 53 00 74 00 61 00 72 00 74 00 20 00 4d 00 65 00 6e 00 75 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 73 00 5c 00 73 00 74 00 61 00 72 00 74 00 75 00 70 00 5c 00 } //00 00  \Start Menu\Programs\startup\
	condition:
		any of ($a_*)
 
}