
rule Trojan_Win32_Zbot_BQ_MTB{
	meta:
		description = "Trojan:Win32/Zbot.BQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_01_0 = {fe 00 40 3d 87 32 41 00 75 f6 43 81 fb ad 8b 01 00 75 } //01 00 
		$a_01_1 = {6f 6e 73 62 77 64 } //01 00 
		$a_01_2 = {77 62 6f 78 73 68 } //00 00 
	condition:
		any of ($a_*)
 
}