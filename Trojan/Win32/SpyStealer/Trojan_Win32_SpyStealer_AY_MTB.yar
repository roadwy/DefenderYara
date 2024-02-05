
rule Trojan_Win32_SpyStealer_AY_MTB{
	meta:
		description = "Trojan:Win32/SpyStealer.AY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {2b f1 8b c6 c1 e0 04 03 45 f4 8b d6 89 45 0c 8b 45 fc 03 c6 50 8d 45 0c c1 ea 05 03 55 e8 50 c7 05 } //01 00 
		$a_03_1 = {31 55 0c 2b 5d 0c 68 b9 79 37 9e 8d 45 fc 50 e8 90 02 04 ff 4d f8 0f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}