
rule Trojan_BAT_Taskun_KAR_MTB{
	meta:
		description = "Trojan:BAT/Taskun.KAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {17 58 08 5d 13 ?? 07 11 09 91 11 ?? 61 07 11 ?? 91 59 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}