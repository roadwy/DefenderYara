
rule Trojan_BAT_GodPotato_FF_MTB{
	meta:
		description = "Trojan:BAT/GodPotato.FF!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {31 00 38 00 66 00 37 00 30 00 37 00 37 00 30 00 2d 00 38 00 65 00 36 00 34 00 2d 00 31 00 31 00 63 00 66 00 2d 00 39 00 61 00 66 00 31 00 2d 00 30 00 30 00 32 00 30 00 61 00 66 00 36 00 65 00 37 00 32 00 66 00 34 00 } //01 00  18f70770-8e64-11cf-9af1-0020af6e72f4
		$a_01_1 = {5b 00 5c 00 70 00 69 00 70 00 65 00 5c 00 65 00 70 00 6d 00 61 00 70 00 70 00 65 00 72 00 5d 00 } //00 00  [\pipe\epmapper]
	condition:
		any of ($a_*)
 
}