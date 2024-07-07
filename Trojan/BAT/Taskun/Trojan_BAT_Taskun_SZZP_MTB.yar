
rule Trojan_BAT_Taskun_SZZP_MTB{
	meta:
		description = "Trojan:BAT/Taskun.SZZP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {61 11 0a 59 20 00 01 00 00 58 20 ff 00 00 00 5f 13 0c } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}