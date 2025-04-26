
rule Trojan_BAT_Remcos_PWH_MTB{
	meta:
		description = "Trojan:BAT/Remcos.PWH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 73 43 00 00 0a 0b 07 72 61 00 00 70 28 ?? ?? ?? 0a 72 93 00 00 70 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 0c 73 46 00 00 0a 0d 09 08 17 73 47 00 00 0a 13 04 11 04 06 16 06 8e 69 6f ?? ?? ?? 0a 09 6f ?? ?? ?? 0a 0a dd 0f 00 00 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}