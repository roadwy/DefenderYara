
rule Trojan_BAT_Fsysna_PTGY_MTB{
	meta:
		description = "Trojan:BAT/Fsysna.PTGY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {73 00 01 00 0a 28 90 01 01 02 00 06 04 6f 01 01 00 0a 28 90 01 01 02 00 06 13 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}