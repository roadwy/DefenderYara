
rule Trojan_BAT_Taskun_EJJJ_MTB{
	meta:
		description = "Trojan:BAT/Taskun.EJJJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {15 5f 13 09 11 09 06 17 17 ?? ?? ?? ?? ?? 5a 06 17 16 ?? ?? ?? ?? ?? 26 16 58 06 17 18 } //1
		$a_01_1 = {00 08 17 58 07 8e 69 5d 0c 00 11 14 17 58 13 14 11 14 11 0f fe 04 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}