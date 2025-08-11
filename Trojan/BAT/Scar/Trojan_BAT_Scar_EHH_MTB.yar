
rule Trojan_BAT_Scar_EHH_MTB{
	meta:
		description = "Trojan:BAT/Scar.EHH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {14 11 06 11 07 ?? ?? ?? ?? ?? 26 09 17 58 0d 11 07 17 58 13 07 11 07 11 06 ?? ?? ?? ?? ?? 32 e1 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}