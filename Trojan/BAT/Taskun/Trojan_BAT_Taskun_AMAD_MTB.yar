
rule Trojan_BAT_Taskun_AMAD_MTB{
	meta:
		description = "Trojan:BAT/Taskun.AMAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {1f 16 5d 91 13 ?? 07 11 ?? 91 11 ?? 61 13 ?? 11 ?? 17 58 13 ?? 07 11 ?? 11 ?? 5d 91 13 ?? 20 00 01 00 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}