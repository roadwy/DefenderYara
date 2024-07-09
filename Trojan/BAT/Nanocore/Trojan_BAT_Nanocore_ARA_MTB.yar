
rule Trojan_BAT_Nanocore_ARA_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 02 8e 69 18 5a 06 8e 69 58 0b 2b 3d 00 02 07 02 8e 69 5d 02 07 02 8e 69 5d 91 06 07 06 8e 69 5d 91 61 28 ?? ?? ?? ?? 02 07 17 58 02 8e 69 5d 91 28 ?? ?? ?? ?? 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 00 07 15 58 0b 07 16 fe 04 16 fe 01 0c 08 2d b8 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}