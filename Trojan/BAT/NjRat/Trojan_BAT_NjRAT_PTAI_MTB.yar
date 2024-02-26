
rule Trojan_BAT_NjRAT_PTAI_MTB{
	meta:
		description = "Trojan:BAT/NjRAT.PTAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {d0 25 00 00 06 26 07 28 90 01 01 02 00 06 28 90 01 01 02 00 06 8e b7 16 fe 02 0d 09 39 4b ff ff ff 17 8d 4e 00 00 01 0c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}