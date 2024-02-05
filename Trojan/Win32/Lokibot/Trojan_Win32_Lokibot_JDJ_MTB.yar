
rule Trojan_Win32_Lokibot_JDJ_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.JDJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_02_0 = {33 c0 33 db 90 01 01 90 1b 00 8b d3 8a 88 90 01 04 88 4d fb 8a 4d fb 80 f1 62 03 d6 88 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}