
rule Trojan_BAT_Convagent_NCF_MTB{
	meta:
		description = "Trojan:BAT/Convagent.NCF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {28 70 00 00 0a 28 90 01 02 00 0a 2c 07 20 90 01 02 00 00 10 03 04 06 6f 90 01 02 00 0a 06 6f 90 01 02 00 0a 28 90 01 02 00 0a 06 6f 90 01 02 00 0a 07 05 6f 90 01 02 00 06 90 00 } //01 00 
		$a_01_1 = {6d 75 63 6c 42 } //01 00 
		$a_01_2 = {54 6f 63 54 6f 65 } //00 00 
	condition:
		any of ($a_*)
 
}