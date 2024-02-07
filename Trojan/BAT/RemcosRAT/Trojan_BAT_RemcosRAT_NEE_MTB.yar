
rule Trojan_BAT_RemcosRAT_NEE_MTB{
	meta:
		description = "Trojan:BAT/RemcosRAT.NEE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {28 14 00 00 0a 28 90 01 03 06 6f 90 01 03 0a 28 90 01 03 06 28 90 01 03 06 13 00 38 90 01 03 00 dd 90 01 03 ff 26 38 90 01 03 00 dd 90 01 03 ff 90 00 } //01 00 
		$a_01_1 = {4e 6a 73 77 70 73 67 } //00 00  Njswpsg
	condition:
		any of ($a_*)
 
}