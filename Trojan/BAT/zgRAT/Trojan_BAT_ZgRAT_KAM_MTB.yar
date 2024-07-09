
rule Trojan_BAT_ZgRAT_KAM_MTB{
	meta:
		description = "Trojan:BAT/ZgRAT.KAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8e 69 5d 1f ?? 58 1f ?? 58 1f ?? 59 1d 58 1d 59 91 61 06 09 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}