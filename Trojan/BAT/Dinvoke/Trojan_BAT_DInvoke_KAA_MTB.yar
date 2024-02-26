
rule Trojan_BAT_DInvoke_KAA_MTB{
	meta:
		description = "Trojan:BAT/DInvoke.KAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {04 1a 5d 1e 5a 1f 1f 5f 63 61 d1 2a } //00 00 
	condition:
		any of ($a_*)
 
}