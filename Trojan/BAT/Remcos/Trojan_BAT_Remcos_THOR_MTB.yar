
rule Trojan_BAT_Remcos_THOR_MTB{
	meta:
		description = "Trojan:BAT/Remcos.THOR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {73 12 00 00 0a 0c 20 05 00 00 00 38 3d 00 00 00 14 0a 17 28 ?? ?? ?? 06 3a 52 00 00 00 26 20 04 00 00 00 38 25 00 00 00 1f 1c 8d 19 00 00 01 25 d0 01 00 00 04 28 ?? ?? ?? 06 0b 38 2a 00 00 00 20 03 00 00 00 fe 0e 06 00 fe 0c 06 00 45 06 00 00 00 96 ff ff ff be ff ff ff 00 00 00 00 a6 ff ff ff be ff ff ff 1a 00 00 00 38 91 ff ff ff } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}