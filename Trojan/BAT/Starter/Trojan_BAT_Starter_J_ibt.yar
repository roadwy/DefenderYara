
rule Trojan_BAT_Starter_J_ibt{
	meta:
		description = "Trojan:BAT/Starter.J!ibt,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {28 1d 00 00 0a 72 01 00 00 70 28 1e 00 00 0a 28 1f 00 00 0a 26 de 0c 28 20 00 00 0a 28 21 00 00 0a de 00 28 1d 00 00 0a 72 90 01 01 00 00 70 28 1e 00 00 0a 28 1f 00 00 0a 26 de 0c 28 20 00 00 0a 28 21 00 00 0a de 00 90 00 } //01 00 
		$a_00_1 = {67 65 74 5f 53 74 61 72 74 75 70 50 61 74 68 } //00 00 
	condition:
		any of ($a_*)
 
}