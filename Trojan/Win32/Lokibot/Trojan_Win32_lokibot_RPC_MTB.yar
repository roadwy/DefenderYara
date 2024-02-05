
rule Trojan_Win32_lokibot_RPC_MTB{
	meta:
		description = "Trojan:Win32/lokibot.RPC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 4d 10 8b 55 94 8a c3 32 45 93 85 c9 75 } //01 00 
		$a_03_1 = {ff 45 80 8b 45 80 3b 45 0c 0f 8c 90 01 04 8b 4d f8 5f 5e 33 cd 5b e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}