
rule Trojan_BAT_AgentTesla_CCDH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CCDH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 11 06 07 8e 69 6a 5d d4 07 11 06 07 8e 69 6a 5d d4 91 08 11 06 1f 16 6a 5d d4 91 61 28 ?? ?? ?? ?? d2 07 11 06 17 6a 58 07 8e 69 6a 5d d4 91 28 ?? ?? ?? ?? d2 59 20 ?? ?? ?? ?? 58 20 ?? ?? ?? ?? 5d 28 ?? ?? ?? ?? d2 9c 00 11 06 17 6a 58 13 06 11 06 07 8e 69 17 59 09 17 58 5a 6a fe 02 16 fe 01 13 07 11 07 2d 96 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}