
rule Trojan_BAT_Remcos_AMAR_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AMAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 0a 16 0b 2b ?? 00 02 07 7e ?? 00 00 04 07 91 03 07 06 8e 69 5d 91 61 d2 9c 00 07 17 58 0b 07 7e ?? 00 00 04 8e 69 fe ?? 0c 08 2d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}