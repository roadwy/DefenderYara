
rule Trojan_BAT_Taskun_ARAF_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ARAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 08 6f c0 00 00 0a 5d 13 06 09 08 6f c0 00 00 0a 5b 13 07 08 72 d5 09 00 70 18 18 8d ?? ?? ?? 01 25 16 11 06 8c ?? ?? ?? 01 a2 25 17 11 07 8c ?? ?? ?? 01 a2 28 ?? ?? ?? 0a a5 33 00 00 01 13 08 12 08 28 c2 00 00 0a 13 09 07 11 09 6f c3 00 00 0a 00 09 17 58 0d 00 09 08 6f c0 00 00 0a 08 6f c4 00 00 0a 5a fe 04 13 0a 11 0a 2d 91 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}