
rule Trojan_BAT_Lazy_AMBE_MTB{
	meta:
		description = "Trojan:BAT/Lazy.AMBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {0a 0c 08 28 90 01 01 00 00 0a 72 90 01 01 00 00 70 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 08 28 90 01 01 00 00 0a 72 90 01 01 00 00 70 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 08 6f 90 01 01 00 00 0a 07 16 07 8e 69 6f 90 01 01 00 00 0a 0d de 0a 90 00 } //01 00 
		$a_80_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  01 00 
		$a_80_2 = {44 65 6c 61 79 } //Delay  00 00 
	condition:
		any of ($a_*)
 
}