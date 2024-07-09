
rule Trojan_Win32_MysticStealer_CCEA_MTB{
	meta:
		description = "Trojan:Win32/MysticStealer.CCEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 4c 38 ?? 0f b6 87 ?? ?? ?? ?? 0f b6 44 38 ?? 03 c8 0f b6 c1 8d 4f ?? 8a 04 08 30 04 13 43 3b 5d ?? 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}