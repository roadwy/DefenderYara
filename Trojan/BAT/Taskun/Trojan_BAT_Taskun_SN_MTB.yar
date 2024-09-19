
rule Trojan_BAT_Taskun_SN_MTB{
	meta:
		description = "Trojan:BAT/Taskun.SN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 11 0f 91 11 10 61 11 11 59 20 00 02 00 00 58 13 12 07 11 0f 11 12 20 ff 00 00 00 5f d2 9c } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}