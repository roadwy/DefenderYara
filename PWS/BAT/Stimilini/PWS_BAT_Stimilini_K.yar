
rule PWS_BAT_Stimilini_K{
	meta:
		description = "PWS:BAT/Stimilini.K,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 01 00 "
		
	strings :
		$a_80_0 = {67 65 74 5f 53 4c 6f 67 69 6e } //get_SLogin  01 00 
		$a_80_1 = {67 65 74 5f 53 4c 6f 67 53 65 63 } //get_SLogSec  02 00 
		$a_80_2 = {4b 69 6c 6c 53 53 46 4e } //KillSSFN  02 00 
		$a_80_3 = {4b 69 6c 6c 53 74 65 61 6d } //KillSteam  03 00 
		$a_80_4 = {49 6e 76 65 6e 74 6f 72 79 53 74 65 61 6c 65 72 } //InventoryStealer  00 00 
		$a_00_5 = {5d 04 00 } //00 47 
	condition:
		any of ($a_*)
 
}