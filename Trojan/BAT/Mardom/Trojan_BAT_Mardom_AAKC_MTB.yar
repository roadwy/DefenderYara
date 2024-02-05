
rule Trojan_BAT_Mardom_AAKC_MTB{
	meta:
		description = "Trojan:BAT/Mardom.AAKC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_03_0 = {07 8e 69 8d 90 01 01 00 00 01 0c 16 0d 38 90 01 02 00 00 08 09 07 09 91 06 09 06 6f 90 01 01 00 00 0a 5d 6f 90 01 01 00 00 0a 61 d2 9c 09 17 58 0d 09 07 8e 69 32 e0 90 00 } //01 00 
		$a_01_1 = {52 65 61 64 41 73 42 79 74 65 41 72 72 61 79 41 73 79 6e 63 } //00 00 
	condition:
		any of ($a_*)
 
}