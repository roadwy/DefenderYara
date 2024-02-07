
rule Trojan_Win32_Turkojan_A_dll{
	meta:
		description = "Trojan:Win32/Turkojan.A!dll,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {4b 42 48 6f 6f 6b 2e 64 6c 6c 00 43 72 65 61 74 65 48 6f 6f 6b 00 44 65 6c 65 74 65 48 6f 6f 6b 00 } //01 00 
		$a_01_1 = {54 68 65 43 61 6e 4d 65 42 75 74 54 68 65 } //03 00  TheCanMeButThe
		$a_03_2 = {f7 c7 00 00 00 80 75 33 83 c3 f0 83 eb 03 0f 92 c0 34 01 0a 05 90 01 02 40 00 74 20 e8 90 01 02 ff ff 50 0f b7 05 90 01 02 40 00 50 68 2c cf 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}