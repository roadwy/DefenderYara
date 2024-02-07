
rule Trojan_BAT_Quasar_NQD_MTB{
	meta:
		description = "Trojan:BAT/Quasar.NQD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {1a 95 58 20 01 60 9f de 61 9e 11 0b 20 90 01 03 60 5a 20 90 01 03 af 61 38 90 01 03 ff 08 08 5a 20 90 01 03 14 6a 5e 0c 20 a7 91 bd 2d 90 00 } //01 00 
		$a_01_1 = {6a 00 75 00 73 00 63 00 68 00 65 00 64 00 } //00 00  jusched
	condition:
		any of ($a_*)
 
}