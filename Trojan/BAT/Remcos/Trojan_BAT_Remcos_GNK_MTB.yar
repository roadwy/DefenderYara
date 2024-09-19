
rule Trojan_BAT_Remcos_GNK_MTB{
	meta:
		description = "Trojan:BAT/Remcos.GNK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 02 16 02 8e 69 6f ?? ?? ?? 0a 0d 09 8e 69 1f 11 59 17 58 8d ?? ?? ?? 01 13 04 09 1f 10 11 04 16 09 8e 69 1f 10 59 28 ?? ?? ?? 0a 11 04 13 05 dd } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}