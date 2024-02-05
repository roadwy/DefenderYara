
rule Trojan_Win32_RemcosRAT_RPC_MTB{
	meta:
		description = "Trojan:Win32/RemcosRAT.RPC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {31 c0 8b 4d ec 8a 14 0d 90 01 04 88 55 eb 8b 4d ec 0f b6 75 eb 90 09 30 00 90 02 20 c7 45 ec 00 00 00 00 c7 45 ec 00 00 00 00 81 7d ec 90 01 02 00 00 0f 83 90 00 } //01 00 
		$a_03_1 = {8b 45 ec 83 c0 01 89 45 ec e9 90 01 04 8d 05 90 01 04 31 c9 89 04 24 c7 44 24 04 00 00 00 00 89 4d e4 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}