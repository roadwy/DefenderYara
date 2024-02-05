
rule Trojan_Win32_Lokibot_FW_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.FW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 4c 24 04 ba 90 01 04 56 2b d1 be 90 01 02 00 00 8a 04 0a 34 90 01 01 88 01 41 4e 75 f5 b8 90 01 02 00 00 5e c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}