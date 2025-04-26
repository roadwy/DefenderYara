
rule Trojan_BAT_Taskun_AMBC_MTB{
	meta:
		description = "Trojan:BAT/Taskun.AMBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 8e 69 5d 13 [0-1e] 07 8e 69 5d 91 13 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}