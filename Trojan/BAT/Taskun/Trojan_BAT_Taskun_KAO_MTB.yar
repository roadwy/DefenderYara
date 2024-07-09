
rule Trojan_BAT_Taskun_KAO_MTB{
	meta:
		description = "Trojan:BAT/Taskun.KAO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 08 91 11 ?? 08 1f ?? 5d 91 61 07 11 ?? 91 59 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}