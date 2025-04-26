
rule Trojan_BAT_Taskun_ARAJ_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ARAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 72 cb 3a 03 70 72 cf 3a 03 70 6f ?? ?? ?? 0a 28 ?? ?? ?? 06 0d 09 72 d5 3a 03 70 72 81 00 00 70 6f ?? ?? ?? 0a 13 04 11 04 6f ?? ?? ?? 0a 18 5b 8d ?? ?? ?? 01 13 05 16 13 08 2b 21 00 11 05 11 08 11 04 11 08 18 5a 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a d2 9c 00 11 08 17 58 13 08 11 08 11 05 8e 69 fe 04 13 09 11 09 2d d1 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}