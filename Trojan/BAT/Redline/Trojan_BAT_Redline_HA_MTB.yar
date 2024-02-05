
rule Trojan_BAT_Redline_HA_MTB{
	meta:
		description = "Trojan:BAT/Redline.HA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_80_0 = {63 75 74 74 2e 6c 79 2f 43 58 41 44 35 44 4c } //cutt.ly/CXAD5DL  01 00 
		$a_80_1 = {54 68 72 65 61 74 44 65 61 6c } //ThreatDeal  01 00 
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00 
		$a_80_3 = {41 68 78 74 6e 72 6d 67 66 6e 69 74 66 77 74 65 73 62 7a 72 6c 61 79 65 } //Ahxtnrmgfnitfwtesbzrlaye  01 00 
		$a_01_4 = {49 43 72 79 70 74 6f 54 72 61 6e 73 66 6f 72 6d } //00 00 
	condition:
		any of ($a_*)
 
}