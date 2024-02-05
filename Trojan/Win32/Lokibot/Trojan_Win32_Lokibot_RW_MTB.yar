
rule Trojan_Win32_Lokibot_RW_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {99 b9 03 00 00 00 f7 90 01 01 8b 90 02 05 0f be 0c 10 8b 90 02 05 0f 90 02 0a 33 c1 8b 90 02 05 88 90 02 0a eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}