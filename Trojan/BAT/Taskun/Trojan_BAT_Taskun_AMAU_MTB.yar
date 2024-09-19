
rule Trojan_BAT_Taskun_AMAU_MTB{
	meta:
		description = "Trojan:BAT/Taskun.AMAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 5d 08 58 08 5d 91 11 [0-05] 61 11 [0-05] 59 20 00 02 00 00 58 } //2
		$a_01_1 = {18 5a 20 00 01 00 00 5d 13 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}