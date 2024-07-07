
rule Trojan_BAT_Taskun_KAM_MTB{
	meta:
		description = "Trojan:BAT/Taskun.KAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 5d d4 91 61 28 90 01 01 00 00 0a 07 11 90 01 01 08 6a 5d d4 91 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}