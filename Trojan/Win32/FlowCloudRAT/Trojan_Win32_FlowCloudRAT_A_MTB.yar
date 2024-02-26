
rule Trojan_Win32_FlowCloudRAT_A_MTB{
	meta:
		description = "Trojan:Win32/FlowCloudRAT.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {8b f8 6a 02 6a 00 57 ff d6 57 ff 15 90 01 04 6a 00 8b d8 6a 90 01 01 57 89 5d fc ff d6 53 ff 15 90 01 04 57 6a 01 8b f0 53 56 ff 15 90 01 04 83 c4 38 6a 90 00 } //02 00 
		$a_03_1 = {6a 00 68 00 00 04 00 ff 15 90 01 04 6a 00 8b d8 8b 45 fc 50 56 8b 35 0c 20 00 10 50 6a 00 53 ff d6 8b 3d 10 20 00 10 50 ff d7 50 ff 15 90 01 04 6a 00 ff 75 fc 6a 00 53 ff d6 50 6a 00 ff 15 90 01 04 50 ff 15 90 01 04 ff d7 50 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}