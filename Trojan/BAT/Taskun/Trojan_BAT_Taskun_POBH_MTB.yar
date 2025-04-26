
rule Trojan_BAT_Taskun_POBH_MTB{
	meta:
		description = "Trojan:BAT/Taskun.POBH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 09 11 08 58 20 ?? ?? ?? ?? 5d 13 09 11 05 17 58 20 ?? ?? ?? ?? 5f 13 05 11 09 11 08 1f 1f 5f 60 13 0a 11 0a 11 05 61 13 0a 11 06 11 04 11 05 95 58 } //6
		$a_03_1 = {09 11 08 07 11 08 91 11 04 11 0b 95 61 d2 9c 11 0c 11 0a 5a 11 08 58 20 ?? ?? ?? ?? 5d 13 0d 11 09 11 0d 61 13 09 11 08 17 58 13 08 } //4
	condition:
		((#a_03_0  & 1)*6+(#a_03_1  & 1)*4) >=10
 
}