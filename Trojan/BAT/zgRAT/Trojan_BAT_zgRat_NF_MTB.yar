
rule Trojan_BAT_ZgRAT_NF_MTB{
	meta:
		description = "Trojan:BAT/ZgRAT.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {fe 0c 06 00 76 6c 58 6d fe ?? ?? 00 5c fe ?? ?? 00 58 fe ?? ?? 00 fe ?? ?? 00 fe ?? ?? 00 59 20 ?? ?? ?? 0b 61 fe ?? ?? 00 20 ?? ?? ?? 00 fe ?? ?? 00 20 ?? ?? ?? 00 5f 5a } //5
		$a_01_1 = {53 58 34 56 50 42 6e 77 72 61 } //1 SX4VPBnwra
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}