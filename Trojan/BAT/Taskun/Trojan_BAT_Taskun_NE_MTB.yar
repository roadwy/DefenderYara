
rule Trojan_BAT_Taskun_NE_MTB{
	meta:
		description = "Trojan:BAT/Taskun.NE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 06 17 58 08 5d 08 58 08 5d 13 } //5
		$a_01_1 = {09 8e 69 5d 09 8e 69 58 09 8e 69 5d } //4
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*4) >=9
 
}