
rule Trojan_BAT_Taskun_MBFQ_MTB{
	meta:
		description = "Trojan:BAT/Taskun.MBFQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 13 0d 28 ?? ?? ?? ?? 14 20 ?? ?? ?? ?? 28 ?? ?? ?? ?? 17 8d ?? ?? ?? ?? 25 16 11 ?? 28 ?? ?? ?? ?? a2 14 14 28 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Taskun_MBFQ_MTB_2{
	meta:
		description = "Trojan:BAT/Taskun.MBFQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 1f 16 5d 91 13 ?? 11 ?? 11 ?? 61 13 ?? 11 ?? 11 ?? 59 13 } //1
		$a_03_1 = {07 06 8e 69 5d 06 07 06 8e 69 5d 91 08 07 08 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 28 ?? 00 00 0a 06 07 17 58 06 8e 69 5d 91 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}