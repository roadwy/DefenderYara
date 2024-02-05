
rule Trojan_Win32_Lokibot_JM_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.JM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8a 12 80 f2 90 01 01 03 c3 73 90 01 01 e8 90 01 03 ff 88 10 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}