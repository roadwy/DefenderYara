
rule Trojan_BAT_Taskun_SRAA_MTB{
	meta:
		description = "Trojan:BAT/Taskun.SRAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {07 06 91 11 0d 61 11 0f 59 20 00 02 00 00 58 13 15 16 13 0a 2b 06 } //3
		$a_01_1 = {11 12 11 09 5a 20 00 02 00 00 5d 26 11 09 17 58 13 09 11 09 19 fe 04 13 1e 11 1e 2d e3 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}