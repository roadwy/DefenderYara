
rule Trojan_BAT_Noancooe_AJ_MTB{
	meta:
		description = "Trojan:BAT/Noancooe.AJ!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {28 04 00 00 06 28 01 00 00 0a 28 02 00 00 0a 6f 03 00 00 0a 14 14 6f 04 00 00 0a 26 16 28 05 00 00 0a dd 06 00 00 00 26 dd 00 00 00 00 2a } //00 00 
	condition:
		any of ($a_*)
 
}