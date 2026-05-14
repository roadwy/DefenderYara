
rule Trojan_BAT_Taskun_ZFH_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ZFH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 11 03 11 04 6f ?? 00 00 0a 13 06 38 ?? 00 00 00 11 02 11 08 28 ?? 00 00 06 13 0a 38 ?? 00 00 00 11 01 73 ?? 00 00 06 13 02 38 ?? fd ff ff 03 72 2b 0e 00 70 28 ?? 00 00 0a 3a ?? ff ff ff 38 ?? 00 00 00 16 13 04 38 25 fe ff ff 11 0a } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}