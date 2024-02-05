
rule Trojan_Win32_Lokibot_JRL_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.JRL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_02_0 = {8b fe 03 f8 90 90 90 90 8b c2 8a 80 90 01 04 90 90 90 90 32 44 24 04 88 07 90 0a 37 00 33 d2 90 90 90 90 33 db 90 90 c6 44 24 90 01 02 8b c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}