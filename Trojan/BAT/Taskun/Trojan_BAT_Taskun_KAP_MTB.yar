
rule Trojan_BAT_Taskun_KAP_MTB{
	meta:
		description = "Trojan:BAT/Taskun.KAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 08 91 11 ?? 61 13 ?? ?? ?? 07 11 ?? 91 59 20 00 01 00 00 58 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}