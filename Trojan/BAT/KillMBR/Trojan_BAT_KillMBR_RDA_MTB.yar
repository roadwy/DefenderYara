
rule Trojan_BAT_KillMBR_RDA_MTB{
	meta:
		description = "Trojan:BAT/KillMBR.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {19 16 7e 1e 00 00 0a 28 ?? ?? ?? ?? 0b 07 06 20 00 80 00 00 12 02 7e 1e 00 00 0a 28 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}