
rule Trojan_BAT_Bladabindi_SPQN_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.SPQN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_01_0 = {07 08 07 08 91 02 08 1f 10 5d 91 61 9c 08 17 58 0c 08 09 31 eb } //00 00 
	condition:
		any of ($a_*)
 
}