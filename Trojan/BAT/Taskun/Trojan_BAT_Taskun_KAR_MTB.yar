
rule Trojan_BAT_Taskun_KAR_MTB{
	meta:
		description = "Trojan:BAT/Taskun.KAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {17 58 08 5d 13 90 01 01 07 11 09 91 11 90 01 01 61 07 11 90 01 01 91 59 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}