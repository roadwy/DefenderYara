
rule Trojan_BAT_Taskun_EHDF_MTB{
	meta:
		description = "Trojan:BAT/Taskun.EHDF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 09 11 0e 8f 0f 00 00 01 25 71 0f 00 00 01 11 0c 11 0e 91 61 d2 81 0f 00 00 01 11 0e 17 58 13 0e 11 0e 11 08 32 d9 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}