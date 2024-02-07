
rule Backdoor_BAT_Bladabindi_NBM_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.NBM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {28 1e 00 00 0a a2 28 90 01 01 00 00 0a 0d 09 28 90 01 01 00 00 0a 07 6f 90 01 01 00 00 0a 18 14 28 90 01 01 00 00 0a 13 04 11 04 28 90 01 01 00 00 0a 08 6f 1d 00 00 0a 17 90 00 } //01 00 
		$a_01_1 = {57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 31 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //01 00  WindowsFormsApp1.Properties.Resources.resources
		$a_01_2 = {65 78 65 32 70 6f 77 65 72 73 68 65 6c 6c 2d 6d 61 73 74 65 72 } //00 00  exe2powershell-master
	condition:
		any of ($a_*)
 
}