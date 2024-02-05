
rule Backdoor_Win32_Draobo_A{
	meta:
		description = "Backdoor:Win32/Draobo.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {5b 4b 45 59 5d 00 90 02 04 5b 2f 4b 45 59 5d 00 90 00 } //01 00 
		$a_00_1 = {00 00 25 00 73 00 25 00 73 00 2a 00 2e 00 2a 00 00 00 } //01 00 
		$a_01_2 = {6a 20 ff 37 ff 76 40 ff 50 3c 83 c7 04 4b 75 eb ff 76 40 } //00 00 
	condition:
		any of ($a_*)
 
}