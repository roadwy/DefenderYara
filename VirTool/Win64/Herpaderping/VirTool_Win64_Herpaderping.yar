
rule VirTool_Win64_Herpaderping{
	meta:
		description = "VirTool:Win64/Herpaderping,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 ff 48 89 bd 10 09 00 00 89 7c 24 40 48 89 7c 24 38 48 89 7c 24 30 4c 89 6c 24 28 c7 44 24 20 04 00 00 00 4c 8d 90 01 02 45 33 c0 ba ff ff 1f 00 48 8d 90 01 05 ff 15 90 01 04 85 c0 90 01 02 48 89 bd 10 09 00 00 90 00 } //01 00 
		$a_03_1 = {4c 89 ad 40 09 00 00 4c 89 ad 28 09 00 00 48 89 5c 24 30 c7 44 24 28 00 00 00 01 c7 44 24 20 02 00 00 00 45 33 c9 45 33 c0 ba 1f 00 0f 00 48 8d 90 01 05 ff 15 90 01 04 85 c0 90 01 02 4c 89 ad 28 09 00 00 90 00 } //01 00 
		$a_03_2 = {48 89 74 24 20 4c 8b cf 49 8b cf ff 15 90 01 04 85 c0 90 01 02 48 8b 8d a8 00 00 00 90 00 } //01 00 
		$a_03_3 = {4c 8b cf 49 c1 e9 20 48 89 74 24 28 89 7c 24 20 33 d2 44 8d 90 01 02 48 8b cd ff 15 90 01 04 48 8b d8 4c 8b f0 48 ff c0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}