
rule Trojan_BAT_RemcosRAT_SL_MTB{
	meta:
		description = "Trojan:BAT/RemcosRAT.SL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {06 72 69 05 00 70 6f 44 00 00 0a 75 1b 00 00 01 20 00 d8 01 00 28 02 00 00 06 0b 28 45 00 00 0a 07 6f 46 00 00 0a } //1
		$a_81_1 = {24 41 39 45 37 43 35 46 38 2d 36 44 34 42 2d 34 41 33 45 2d 39 46 32 43 2d 38 42 31 41 37 44 36 45 35 46 34 43 } //1 $A9E7C5F8-6D4B-4A3E-9F2C-8B1A7D6E5F4C
	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}