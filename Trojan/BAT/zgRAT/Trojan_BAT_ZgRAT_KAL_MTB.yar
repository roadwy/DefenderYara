
rule Trojan_BAT_ZgRAT_KAL_MTB{
	meta:
		description = "Trojan:BAT/ZgRAT.KAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 03 11 02 28 ?? 00 00 06 5d 28 ?? 00 00 06 61 d2 9c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}