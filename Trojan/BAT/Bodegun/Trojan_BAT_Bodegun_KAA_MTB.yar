
rule Trojan_BAT_Bodegun_KAA_MTB{
	meta:
		description = "Trojan:BAT/Bodegun.KAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {2b 1f 00 06 72 90 01 01 00 00 70 02 07 91 8c 90 01 01 00 00 01 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 26 00 07 17 58 0b 07 02 8e 69 fe 04 0d 09 2d d7 90 00 } //05 00 
		$a_01_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 70 00 77 00 6e 00 2e 00 75 00 70 00 68 00 65 00 72 00 6f 00 2e 00 63 00 6f 00 6d 00 2f 00 } //00 00  http://pwn.uphero.com/
	condition:
		any of ($a_*)
 
}