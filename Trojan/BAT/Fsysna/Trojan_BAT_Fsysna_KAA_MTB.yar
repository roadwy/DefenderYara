
rule Trojan_BAT_Fsysna_KAA_MTB{
	meta:
		description = "Trojan:BAT/Fsysna.KAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {06 07 06 07 93 19 5b d1 9d 07 17 58 0b 07 06 8e 69 } //00 00 
	condition:
		any of ($a_*)
 
}