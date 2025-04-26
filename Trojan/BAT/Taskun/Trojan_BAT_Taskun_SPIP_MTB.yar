
rule Trojan_BAT_Taskun_SPIP_MTB{
	meta:
		description = "Trojan:BAT/Taskun.SPIP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {91 61 07 08 17 6a 58 07 8e 69 6a 5d d4 91 28 ?? ?? ?? 0a 59 11 0a 58 11 0a 5d 28 ?? ?? ?? 0a 9c 08 17 6a 58 0c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}