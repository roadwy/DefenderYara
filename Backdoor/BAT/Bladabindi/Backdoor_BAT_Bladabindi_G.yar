
rule Backdoor_BAT_Bladabindi_G{
	meta:
		description = "Backdoor:BAT/Bladabindi.G,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 43 00 6c 00 61 00 73 00 73 00 65 00 73 00 5c 00 } //02 00  Software\Classes\
		$a_01_1 = {2f 00 63 00 20 00 73 00 74 00 61 00 72 00 74 00 20 00 } //02 00  /c start 
		$a_01_2 = {5c 00 44 00 65 00 66 00 61 00 75 00 6c 00 74 00 49 00 63 00 6f 00 6e 00 5c 00 } //04 00  \DefaultIcon\
		$a_01_3 = {26 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 20 00 2f 00 72 00 6f 00 6f 00 74 00 2c 00 22 00 25 00 43 00 44 00 25 00 } //00 00  &explorer /root,"%CD%
		$a_00_4 = {80 10 00 00 51 e8 } //9d 08 
	condition:
		any of ($a_*)
 
}