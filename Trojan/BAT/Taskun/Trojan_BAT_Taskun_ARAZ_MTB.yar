
rule Trojan_BAT_Taskun_ARAZ_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ARAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 07 06 8e 69 5d 06 07 06 8e 69 5d 91 11 0f 07 1f 16 5d 6f ?? ?? ?? 0a 61 28 ?? ?? ?? 0a 06 07 17 58 06 8e 69 5d 91 28 ?? ?? ?? 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d 28 ?? ?? ?? 0a 9c 07 15 58 0b 07 16 fe 04 16 fe 01 13 12 11 12 2d b0 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}