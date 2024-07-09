
rule Trojan_BAT_Phemedrone_AO_MTB{
	meta:
		description = "Trojan:BAT/Phemedrone.AO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {fe 0e 04 00 fe 0c 03 00 fe 0c 04 00 61 d1 fe 0e 05 00 fe 0c 01 00 fe 0c 05 00 6f } //2
		$a_03_1 = {fe 0c 00 00 fe 0c 02 00 91 fe 0e 03 00 7e ?? 00 00 04 fe 0c 02 00 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}