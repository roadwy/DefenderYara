
rule Trojan_BAT_Remcos_GVA_MTB{
	meta:
		description = "Trojan:BAT/Remcos.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 0d 6f ff 0d 00 06 13 17 11 0d 6f ff 0d 00 06 13 18 11 04 11 17 11 18 6f 5c 02 00 0a 11 16 17 58 13 16 11 16 11 0c 3f d4 ff ff ff } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}