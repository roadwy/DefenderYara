
rule Trojan_BAT_Taskun_SPFM_MTB{
	meta:
		description = "Trojan:BAT/Taskun.SPFM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {69 6a 5d d4 91 58 11 90 01 01 09 95 58 20 ff 00 00 00 5f 13 04 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}