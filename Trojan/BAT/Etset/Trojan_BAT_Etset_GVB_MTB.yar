
rule Trojan_BAT_Etset_GVB_MTB{
	meta:
		description = "Trojan:BAT/Etset.GVB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {72 01 00 00 70 28 05 00 00 0a 0a 28 06 00 00 0a 28 07 00 00 0a 0c 12 02 fe 16 08 00 00 01 6f 08 00 00 0a 72 b6 1a ca 70 28 09 00 00 0a 28 0a 00 00 0a 0b 07 06 28 0b 00 00 0a 07 28 0c 00 00 0a 26 2a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}