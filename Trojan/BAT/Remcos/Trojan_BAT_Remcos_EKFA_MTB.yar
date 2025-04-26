
rule Trojan_BAT_Remcos_EKFA_MTB{
	meta:
		description = "Trojan:BAT/Remcos.EKFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {fe 0c 06 00 fe 0c 0b 00 fe 0c 04 00 fe 0c 0b 00 fe 0c 04 00 8e 69 5d 91 fe 0c 01 00 fe 0c 0b 00 91 61 b4 9c 00 fe 0c 0b 00 20 01 00 00 00 d6 fe 0e 0b 00 fe 0c 0b 00 fe 0c 07 00 fe 02 20 00 00 00 00 fe 01 fe 0e 0c 00 fe 0c 0c 00 3a ae ff ff ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}