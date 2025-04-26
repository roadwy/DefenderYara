
rule Trojan_Win32_MarsStealer_RPX_MTB{
	meta:
		description = "Trojan:Win32/MarsStealer.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 ff 8b d0 c1 ea 05 03 d5 8b c8 c1 e1 04 } //1
		$a_01_1 = {8b 44 24 20 31 44 24 10 8b 44 24 10 29 44 24 1c c7 44 24 18 00 00 00 00 8b 44 24 34 01 44 24 18 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}