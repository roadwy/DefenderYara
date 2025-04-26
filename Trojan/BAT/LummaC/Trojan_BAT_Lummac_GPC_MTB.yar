
rule Trojan_BAT_Lummac_GPC_MTB{
	meta:
		description = "Trojan:BAT/Lummac.GPC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 08 06 09 91 9c 06 09 11 ?? 9c 06 08 91 06 09 91 58 20 00 01 00 00 5d [0-2f] 91 61 d2 81 1d 00 00 01 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}