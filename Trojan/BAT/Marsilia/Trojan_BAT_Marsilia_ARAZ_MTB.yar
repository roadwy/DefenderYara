
rule Trojan_BAT_Marsilia_ARAZ_MTB{
	meta:
		description = "Trojan:BAT/Marsilia.ARAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 09 11 06 58 28 ?? ?? ?? 2b 04 11 06 28 ?? ?? ?? 2b 2e 04 16 0c 2b 0b 11 06 17 58 13 06 11 06 07 32 dd } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}