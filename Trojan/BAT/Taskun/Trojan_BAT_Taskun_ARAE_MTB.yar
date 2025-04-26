
rule Trojan_BAT_Taskun_ARAE_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ARAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {72 0f 50 02 70 72 15 50 02 70 6f 65 00 00 0a } //2
		$a_03_1 = {08 11 05 07 11 05 18 5a 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a d2 9c 00 11 05 17 58 13 05 11 05 08 8e 69 fe 04 13 06 11 06 2d d4 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}