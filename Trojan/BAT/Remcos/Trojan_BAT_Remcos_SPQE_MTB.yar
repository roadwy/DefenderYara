
rule Trojan_BAT_Remcos_SPQE_MTB{
	meta:
		description = "Trojan:BAT/Remcos.SPQE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {07 16 93 17 58 d1 9d 08 17 58 d1 0c 08 } //00 00 
	condition:
		any of ($a_*)
 
}