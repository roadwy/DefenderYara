
rule Trojan_BAT_NjRAT_KAAB_MTB{
	meta:
		description = "Trojan:BAT/NjRAT.KAAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 08 9a 0b 06 07 18 28 ?? 01 00 0a 28 ?? 01 00 0a 28 ?? 01 00 0a 28 ?? 01 00 0a 0a 08 17 d6 0c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}