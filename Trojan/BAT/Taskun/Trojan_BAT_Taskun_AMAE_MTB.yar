
rule Trojan_BAT_Taskun_AMAE_MTB{
	meta:
		description = "Trojan:BAT/Taskun.AMAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {1f 16 5d 91 13 ?? 07 11 ?? 91 11 ?? 61 13 ?? 11 ?? 17 58 13 ?? 07 11 ?? 08 5d 91 13 ?? 20 00 01 00 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Taskun_AMAE_MTB_2{
	meta:
		description = "Trojan:BAT/Taskun.AMAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {17 58 08 5d 13 ?? 07 11 ?? 91 11 ?? 61 13 ?? 07 11 ?? 91 13 ?? 02 11 ?? 11 ?? 59 28 ?? ?? ?? ?? 13 0a 07 11 ?? 11 ?? 28 ?? ?? ?? ?? 9c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}