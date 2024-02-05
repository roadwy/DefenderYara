
rule Spyware_BAT_Keylogger_G_MTB{
	meta:
		description = "Spyware:BAT/Keylogger.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_80_0 = {5c 55 6c 74 72 61 4e 69 63 5c 55 6c 74 72 61 4e 69 63 5c } //\UltraNic\UltraNic\  01 00 
		$a_80_1 = {2f 6c 6f 67 2e 74 78 74 } ///log.txt  01 00 
		$a_80_2 = {67 65 74 5f 50 61 73 73 77 6f 72 64 } //get_Password  01 00 
		$a_80_3 = {3c 53 48 49 46 54 3e } //<SHIFT>  01 00 
		$a_80_4 = {3c 43 54 52 4c 3e } //<CTRL>  00 00 
	condition:
		any of ($a_*)
 
}