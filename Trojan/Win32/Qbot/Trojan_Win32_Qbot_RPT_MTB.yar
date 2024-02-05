
rule Trojan_Win32_Qbot_RPT_MTB{
	meta:
		description = "Trojan:Win32/Qbot.RPT!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f b6 0d 97 f9 08 10 3b f9 74 25 00 98 90 f9 08 10 8b d3 8b cb 83 e8 02 2b ce 8d b1 10 67 01 00 8d 0c 7a 8d be 40 f8 ff ff 03 f9 83 f8 03 7f d0 } //00 00 
	condition:
		any of ($a_*)
 
}