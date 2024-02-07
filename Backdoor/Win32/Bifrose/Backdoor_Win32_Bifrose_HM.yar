
rule Backdoor_Win32_Bifrose_HM{
	meta:
		description = "Backdoor:Win32/Bifrose.HM,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {42 69 66 72 6f 73 74 20 52 65 6d 6f 74 65 20 43 6f 6e 74 72 6f 6c 6c 65 72 } //01 00  Bifrost Remote Controller
		$a_01_1 = {25 63 25 75 7c 25 75 7c 25 75 7c 25 75 7c 25 75 7c } //01 00  %c%u|%u|%u|%u|%u|
		$a_01_2 = {3c 25 75 2d 25 2e 32 75 2d 25 2e 32 75 20 25 2e 32 75 3a 25 2e 32 75 3e 3c 25 73 3e } //01 00  <%u-%.2u-%.2u %.2u:%.2u><%s>
		$a_03_3 = {6b 61 76 73 76 63 2e 65 78 65 00 90 01 01 6b 61 76 2e 65 78 65 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}