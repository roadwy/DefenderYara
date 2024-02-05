
rule Trojan_Win32_Lokibot_J_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.J!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {41 39 d1 75 f7 90 0a 1f 00 ba 90 01 02 00 00 31 c9 80 34 01 a3 41 39 d1 75 f7 05 90 01 02 00 00 ff e0 90 00 } //01 00 
		$a_02_1 = {51 54 6a 40 68 90 01 02 00 00 50 e8 90 01 03 ff 5a c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}