
rule Trojan_BAT_Remcos_AWKN_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AWKN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 06 08 06 8e 69 5d 91 02 08 91 61 d2 6f ?? ?? ?? 0a 08 17 58 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}