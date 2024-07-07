
rule Trojan_BAT_Taskun_SPXM_MTB{
	meta:
		description = "Trojan:BAT/Taskun.SPXM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {5d 91 11 0b 61 13 0c 07 11 09 07 8e 69 5d 91 13 0d } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}