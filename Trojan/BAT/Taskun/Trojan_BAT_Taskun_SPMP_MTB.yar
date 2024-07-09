
rule Trojan_BAT_Taskun_SPMP_MTB{
	meta:
		description = "Trojan:BAT/Taskun.SPMP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {5d 13 0a 08 07 02 08 07 91 11 09 61 08 11 0a 91 59 28 ?? ?? 00 06 28 ?? ?? 00 ?? 9c 07 17 58 0b } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}