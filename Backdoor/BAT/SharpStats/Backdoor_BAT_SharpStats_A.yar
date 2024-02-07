
rule Backdoor_BAT_SharpStats_A{
	meta:
		description = "Backdoor:BAT/SharpStats.A,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {55 00 48 00 49 00 52 00 45 00 52 00 38 00 37 00 34 00 38 00 39 00 33 00 55 00 49 00 55 00 4f 00 46 00 55 00 47 00 48 00 45 00 57 00 52 00 4f 00 55 00 49 00 52 00 47 00 48 00 33 00 35 00 } //0a 00  UHIRER874893UIUOFUGHEWROUIRGH35
		$a_01_1 = {74 00 65 00 6d 00 70 00 5f 00 67 00 68 00 5f 00 31 00 32 00 2e 00 64 00 61 00 74 00 } //0a 00  temp_gh_12.dat
		$a_01_2 = {5c 47 6f 6f 67 6c 65 55 70 64 61 74 65 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 47 6f 6f 67 6c 65 55 70 64 61 74 65 2e 70 64 62 } //00 00  \GoogleUpdate\obj\Release\GoogleUpdate.pdb
	condition:
		any of ($a_*)
 
}