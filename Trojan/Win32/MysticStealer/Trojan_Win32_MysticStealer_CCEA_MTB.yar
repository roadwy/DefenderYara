
rule Trojan_Win32_MysticStealer_CCEA_MTB{
	meta:
		description = "Trojan:Win32/MysticStealer.CCEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 4c 38 90 01 01 0f b6 87 90 01 04 0f b6 44 38 90 01 01 03 c8 0f b6 c1 8d 4f 90 01 01 8a 04 08 30 04 13 43 3b 5d 90 01 01 72 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}