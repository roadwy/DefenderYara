
rule Trojan_Win32_LokiBot_KM_MTB{
	meta:
		description = "Trojan:Win32/LokiBot.KM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {d1 e0 0b d0 88 95 90 01 04 0f b6 8d 90 01 04 33 8d 90 01 04 88 8d 90 01 04 0f b6 95 90 01 04 81 c2 8c 00 00 00 88 95 90 01 04 0f b6 85 90 01 04 f7 d8 88 85 90 01 04 8b 8d 90 01 04 8a 95 90 01 04 88 94 0d 90 01 04 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}