
rule Trojan_BAT_Marsilia_SAL_MTB{
	meta:
		description = "Trojan:BAT/Marsilia.SAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 16 0c 2b 19 00 06 08 7e ?? ?? ?? 04 08 91 07 08 07 8e 69 5d 91 61 d2 9c 00 08 17 58 0c 08 7e ?? ?? ?? 04 8e 69 fe 04 0d 09 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}