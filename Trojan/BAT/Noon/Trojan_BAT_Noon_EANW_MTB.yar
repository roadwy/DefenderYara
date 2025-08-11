
rule Trojan_BAT_Noon_EANW_MTB{
	meta:
		description = "Trojan:BAT/Noon.EANW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 09 11 39 16 9c 11 39 17 58 13 39 11 39 1f 0a 11 09 8e 69 ?? ?? ?? ?? ?? 32 e5 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}