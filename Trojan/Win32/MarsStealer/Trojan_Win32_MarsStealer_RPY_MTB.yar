
rule Trojan_Win32_MarsStealer_RPY_MTB{
	meta:
		description = "Trojan:Win32/MarsStealer.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 f6 8b cf c1 e1 04 03 4c 24 2c 8b c7 c1 e8 05 03 44 24 3c 8d 14 3b 33 ca 89 44 24 1c 89 4c 24 14 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}