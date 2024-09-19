
rule Trojan_BAT_Vidar_KAF_MTB{
	meta:
		description = "Trojan:BAT/Vidar.KAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 11 1c 91 61 d2 81 ?? 00 00 01 11 13 17 58 13 13 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}