
rule Trojan_Win32_Trickbot_RD_MSR{
	meta:
		description = "Trojan:Win32/Trickbot.RD!MSR,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {8b 9c 24 4c 01 00 00 8d 54 04 14 33 c0 8a 02 8a 1c 1e 03 d8 03 d9 81 e3 ff 00 00 00 8b cb 8a 5c 0c 14 88 1a 88 44 0c 14 8d 46 01 99 f7 bc 24 50 01 00 00 8b 44 24 10 40 3d 2b 01 00 00 89 44 24 10 8b f2 7c bb } //00 00 
	condition:
		any of ($a_*)
 
}