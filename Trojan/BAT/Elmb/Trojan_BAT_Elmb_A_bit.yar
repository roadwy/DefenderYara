
rule Trojan_BAT_Elmb_A_bit{
	meta:
		description = "Trojan:BAT/Elmb.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 6c 65 65 70 00 67 65 74 5f 49 73 41 6c 69 76 65 00 45 6c 6d 30 44 } //01 00 
		$a_01_1 = {54 65 72 74 69 61 72 79 49 6e 76 6f 6b 65 } //00 00 
	condition:
		any of ($a_*)
 
}