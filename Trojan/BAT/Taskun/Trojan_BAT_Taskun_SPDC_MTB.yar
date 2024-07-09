
rule Trojan_BAT_Taskun_SPDC_MTB{
	meta:
		description = "Trojan:BAT/Taskun.SPDC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {d4 91 61 28 ?? ?? ?? 0a 07 11 ?? 08 6a 5d d4 91 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}