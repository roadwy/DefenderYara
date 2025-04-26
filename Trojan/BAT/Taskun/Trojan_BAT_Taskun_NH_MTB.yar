
rule Trojan_BAT_Taskun_NH_MTB{
	meta:
		description = "Trojan:BAT/Taskun.NH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 0e 11 10 61 13 11 } //5
		$a_01_1 = {11 06 11 0f 20 ff 00 00 00 5f 95 d2 } //4
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*4) >=9
 
}