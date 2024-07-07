
rule Trojan_Win32_Lokibot_SX_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b cb 8b c1 23 c6 8a 44 05 f4 30 81 90 01 04 41 81 f9 90 01 04 72 e9 68 90 01 04 68 90 01 04 68 90 01 04 68 90 01 04 b8 90 01 04 ff 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}