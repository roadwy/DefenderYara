
rule Trojan_BAT_Tnega_M_MTB{
	meta:
		description = "Trojan:BAT/Tnega.M!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {44 3a 5c 4f 6e 65 44 72 69 76 65 5c 50 72 6f 6a 65 63 74 73 5c 4f 6e 65 44 72 69 76 65 54 69 6d 65 72 5c 4f 6e 65 44 72 69 76 65 54 69 6d 65 72 55 49 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 4f 6e 65 44 72 69 76 65 54 69 6d 65 72 55 49 2e 70 64 62 } //1 D:\OneDrive\Projects\OneDriveTimer\OneDriveTimerUI\obj\Release\OneDriveTimerUI.pdb
		$a_81_1 = {4f 6e 65 44 72 69 76 65 54 69 6d 65 72 55 49 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 OneDriveTimerUI.Properties.Resources
		$a_01_2 = {4f 00 6e 00 65 00 44 00 72 00 69 00 76 00 65 00 54 00 69 00 6d 00 65 00 72 00 55 00 49 00 2e 00 65 00 78 00 65 00 } //1 OneDriveTimerUI.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}