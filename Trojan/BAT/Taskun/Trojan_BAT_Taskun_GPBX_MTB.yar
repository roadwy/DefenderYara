
rule Trojan_BAT_Taskun_GPBX_MTB{
	meta:
		description = "Trojan:BAT/Taskun.GPBX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {5f 6a 61 d2 9c 00 11 ?? 17 6a 58 13 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}