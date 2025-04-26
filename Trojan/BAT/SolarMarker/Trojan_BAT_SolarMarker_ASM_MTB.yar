
rule Trojan_BAT_SolarMarker_ASM_MTB{
	meta:
		description = "Trojan:BAT/SolarMarker.ASM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0c 2b 3a 00 08 03 7b ?? ?? ?? 04 8e 69 fe 04 16 fe 01 13 08 11 08 2d 0f 00 07 08 03 7b ?? ?? ?? 04 08 91 9c 00 2b 11 00 07 08 06 08 03 7b ?? ?? ?? 04 8e 69 59 91 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}