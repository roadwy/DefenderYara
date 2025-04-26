
rule Trojan_BAT_Injuke_AMAE_MTB{
	meta:
		description = "Trojan:BAT/Injuke.AMAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 17 58 11 ?? 5d 13 ?? 02 08 07 91 11 ?? 61 08 11 ?? 91 59 28 ?? ?? ?? ?? 13 ?? 08 07 11 ?? 28 ?? ?? ?? ?? d2 9c 07 17 58 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}