
rule TrojanDropper_Win32_Bancos_XP{
	meta:
		description = "TrojanDropper:Win32/Bancos.XP,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 03 00 "
		
	strings :
		$a_01_0 = {0f b6 74 10 ff 8b c7 c1 e0 08 03 f0 8b fe 83 c3 08 83 fb 06 7c 4d } //01 00 
		$a_01_1 = {49 66 20 65 78 69 73 74 20 22 25 73 22 20 47 6f 74 6f 20 31 } //01 00 
		$a_01_2 = {75 70 74 69 6d 65 2e 6c 6f 67 } //00 00 
	condition:
		any of ($a_*)
 
}