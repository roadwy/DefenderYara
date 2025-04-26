
rule Trojan_BAT_DarkCloud_AMDG_MTB{
	meta:
		description = "Trojan:BAT/DarkCloud.AMDG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 0c 08 07 17 73 ?? 00 00 0a 0d 09 03 16 03 8e 69 6f ?? 00 00 0a 08 6f ?? 00 00 0a 13 04 dd 90 0a 44 00 73 ?? 00 00 0a 0a 06 72 ?? ?? 00 70 28 ?? 00 00 0a 72 ?? ?? 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 0b 73 ?? 00 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}