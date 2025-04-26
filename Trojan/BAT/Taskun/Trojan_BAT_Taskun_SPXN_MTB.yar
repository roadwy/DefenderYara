
rule Trojan_BAT_Taskun_SPXN_MTB{
	meta:
		description = "Trojan:BAT/Taskun.SPXN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {5d 91 61 13 0a 11 0a 07 11 04 17 58 09 5d 91 59 20 ?? ?? ?? 00 58 20 ?? ?? ?? 00 5d d2 13 0b } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}