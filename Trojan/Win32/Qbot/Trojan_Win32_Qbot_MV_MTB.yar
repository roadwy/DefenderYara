
rule Trojan_Win32_Qbot_MV_MTB{
	meta:
		description = "Trojan:Win32/Qbot.MV!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {75 12 46 89 7d e4 31 ff 0b 7d fc 89 f8 8b 7d e4 0f b6 1c 30 89 45 e4 83 e0 00 33 45 f0 83 e2 00 31 c2 8b 45 e4 d3 c2 23 d3 ac 0a c2 88 07 47 ff 4d ec 75 b9 } //00 00 
	condition:
		any of ($a_*)
 
}