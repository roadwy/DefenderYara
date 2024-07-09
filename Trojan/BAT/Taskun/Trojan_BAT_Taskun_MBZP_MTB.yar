
rule Trojan_BAT_Taskun_MBZP_MTB{
	meta:
		description = "Trojan:BAT/Taskun.MBZP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {5d d4 91 08 11 ?? 69 1f ?? 5d 6f ?? ?? ?? 0a 13 ?? 11 ?? 61 11 ?? 59 13 ?? 11 ?? 20 00 01 00 00 58 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}